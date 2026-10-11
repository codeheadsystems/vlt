//! The invite, the enrollment request object, the comparison code, and the vault configuration
//! line.

use crate::FORMAT_VERSION;
use crate::codec::{Reader, Writer};
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::ext::{ExtCtx, ExtList};
use crate::limits::INVITE_MAX;
use crate::path::{is_valid_label, is_valid_prefix};
use crate::prim::{hkdf32, open, seal, sha256};
use crate::rng::{draw, os};
use crate::secret::{InviteKey, InviteSecret, SecretString};
use crate::textcodec::{b64url_decode, b64url_into, crock, crock_decode};
use crate::wrap::{KEM_EK_LEN, check_kem_ek};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

const INVITE_PREFIX: &str = "vlt-invite:1:";
const REQ_MAGIC: &[u8; 4] = b"VLTR";
/// Length of the request's cleartext prefix, which is also its associated data.
pub const REQUEST_PREFIX_LEN: usize = 64;

/// An invite. It holds the new device's AWS key, so it is a secret as a whole.
pub struct Invite {
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// The new device's ID.
    pub device_id: [u8; 16],
    /// The inviting device's current epoch.
    pub epoch: u32,
    /// Fingerprint of that epoch's vault key.
    pub fingerprint: [u8; 32],
    /// The inviting device's legacy pin.
    pub legacy_sha256: [u8; 32],
    /// Secret that keys the request.
    pub invite_secret: InviteSecret,
    /// The new device's label.
    pub label: String,
    /// S3 endpoint; empty for AWS.
    pub endpoint: String,
    /// Region.
    pub region: String,
    /// Bucket.
    pub bucket: String,
    /// Prefix.
    pub prefix: String,
    /// The new device's access key ID.
    pub access_key_id: SecretString,
    /// The new device's secret access key.
    pub secret_access_key: SecretString,
    /// Extension list.
    pub ext: ExtList,
}

/// Bucket names: 3 to 63 characters from `[a-z0-9.-]`, starting and ending with a letter or digit.
pub fn is_valid_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        && b.as_bytes()[0].is_ascii_alphanumeric()
        && b.as_bytes()[b.len() - 1].is_ascii_alphanumeric()
}

/// Regions: 1 to 32 characters from `[a-z0-9-]`.
pub fn is_valid_region(r: &str) -> bool {
    (1..=32).contains(&r.len())
        && r.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Endpoints: empty, or an absolute `https://` URL with a host, an optional port, an optional
/// path, and no user information, query, or fragment. `http://` is accepted only for a loopback
/// host, or when `allow_http` is set. Hosts are a DNS name over `[A-Za-z0-9.-]` or a bracketed IPv6
/// literal.
pub fn is_valid_endpoint(e: &str, allow_http: bool) -> bool {
    if e.is_empty() {
        return true;
    }
    let (rest, http) = if let Some(r) = e.strip_prefix("https://") {
        (r, false)
    } else if let Some(r) = e.strip_prefix("http://") {
        (r, true)
    } else {
        return false;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b))
    {
        return false;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some(end) = inner.find(']') else {
            return false;
        };
        let lit = &inner[..end];
        if lit.is_empty()
            || !lit
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return false;
        }
        (&authority[..end + 2], &inner[end + 1..])
    } else {
        match authority.find(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        }
    };
    if !port.is_empty() {
        let Some(digits) = port.strip_prefix(':') else {
            return false;
        };
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || digits.parse::<u16>().is_err()
        {
            return false;
        }
    }
    let dns_ok = !host.starts_with('[')
        && !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if !host.starts_with('[') && !dns_ok {
        return false;
    }
    !http || allow_http || is_loopback(host)
}

fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host == "[::1]" {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets[0] == "127"
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.bytes().all(|b| b.is_ascii_digit())
                && o.parse::<u8>().is_ok()
        })
}

fn check_location(
    endpoint: &str,
    region: &str,
    bucket: &str,
    prefix: &str,
    allow_http: bool,
) -> Result<()> {
    if !is_valid_endpoint(endpoint, allow_http) {
        return input(InputKind::Endpoint);
    }
    if !is_valid_region(region) {
        return input(InputKind::Region);
    }
    if !is_valid_bucket(bucket) {
        return input(InputKind::Bucket);
    }
    if !is_valid_prefix(prefix) {
        return input(InputKind::Prefix);
    }
    Ok(())
}

impl Invite {
    /// The invite's text form, `vlt-invite:1:` and base64url.
    pub fn to_text(&self) -> Result<SecretString> {
        if !is_valid_label(&self.label) {
            return input(InputKind::Label);
        }
        check_location(
            &self.endpoint,
            &self.region,
            &self.bucket,
            &self.prefix,
            true,
        )?;
        self.ext
            .check(ExtCtx::Other)
            .map_err(|_| Error::InvalidInput(InputKind::Ext))?;
        let mut w = Writer::new();
        w.bytes(&self.vault_id)
            .bytes(&self.device_id)
            .u32(self.epoch)
            .bytes(&self.fingerprint);
        w.bytes(&self.legacy_sha256)
            .bytes(self.invite_secret.expose());
        for s in [
            &self.label,
            &self.endpoint,
            &self.region,
            &self.bucket,
            &self.prefix,
        ] {
            w.str16(s.as_bytes())?;
        }
        w.str16(self.access_key_id.as_bytes())?;
        w.str16(self.secret_access_key.as_bytes())?;
        self.ext.encode(&mut w)?;
        let payload = w.into_secret();
        let mut text = Zeroizing::new(String::with_capacity(
            INVITE_PREFIX.len() + payload.len().div_ceil(3) * 4,
        ));
        text.push_str(INVITE_PREFIX);
        b64url_into(&mut text, &payload);
        if text.len() > INVITE_MAX {
            return input(InputKind::TooLarge);
        }
        Ok(text)
    }

    /// Decode an invite strictly, including the label, prefix, bucket, region, and endpoint rules.
    /// `allow_http` admits a plain `http://` endpoint to a non-loopback host.
    pub fn from_text(text: &str, allow_http: bool) -> Result<Invite> {
        let text = text.trim();
        if text.len() > INVITE_MAX {
            return integrity(K::SizeLimit);
        }
        let b = text
            .strip_prefix(INVITE_PREFIX)
            .ok_or(Error::Integrity(K::BadMagic))?;
        let payload = Zeroizing::new(b64url_decode(b)?);
        let mut r = Reader::new(&payload);
        let vault_id = r.array()?;
        let device_id = r.array()?;
        let epoch = r.u32()?;
        let fingerprint = r.array()?;
        let legacy_sha256 = r.array()?;
        let invite_secret = InviteSecret::from_bytes(r.array()?);
        let mut s = || -> Result<String> { Ok(r.str16()?.to_owned()) };
        let (label, endpoint, region, bucket, prefix) = (s()?, s()?, s()?, s()?, s()?);
        let access_key_id = Zeroizing::new(r.str16()?.to_owned());
        let secret_access_key = Zeroizing::new(r.str16()?.to_owned());
        let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
        r.finish()?;
        if !is_valid_label(&label) {
            return integrity(K::LabelRule);
        }
        if !is_valid_prefix(&prefix) {
            return integrity(K::PrefixRule);
        }
        check_location(&endpoint, &region, &bucket, &prefix, allow_http).map_err(|e| {
            Error::Integrity(match e {
                Error::InvalidInput(InputKind::Endpoint) => K::EndpointRule,
                Error::InvalidInput(InputKind::Region) => K::RegionRule,
                Error::InvalidInput(InputKind::Bucket) => K::BucketRule,
                _ => K::PrefixRule,
            })
        })?;
        Ok(Invite {
            vault_id,
            device_id,
            epoch,
            fingerprint,
            legacy_sha256,
            invite_secret,
            label,
            endpoint,
            region,
            bucket,
            prefix,
            access_key_id,
            secret_access_key,
            ext,
        })
    }

    pub(crate) fn key(&self) -> InviteKey {
        invite_key(&self.invite_secret, &self.vault_id)
    }
}

pub(crate) fn invite_key(secret: &InviteSecret, vault_id: &[u8; 16]) -> InviteKey {
    InviteKey::from_zeroizing(hkdf32(secret.expose(), vault_id, b"vlt/v1/invite"))
}

/// The plaintext of an enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    /// Device kind, 1 to 4.
    pub kind: u8,
    /// X25519 public key.
    pub device_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub kem_ek: Vec<u8>,
    /// Extension list.
    pub ext: ExtList,
}

pub(crate) fn seal_request_with_key(
    key: &InviteKey,
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
    req: &EnrollmentRequest,
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    if !(1..=4).contains(&req.kind) {
        return input(InputKind::DeviceKind);
    }
    check_kem_ek(&req.kem_ek).map_err(|_| Error::InvalidInput(InputKind::Keyring))?;
    req.ext
        .check(ExtCtx::Other)
        .map_err(|_| Error::InvalidInput(InputKind::Ext))?;
    let mut w = Writer::new();
    w.bytes(REQ_MAGIC)
        .u16(FORMAT_VERSION)
        .u16(0)
        .bytes(vault_id)
        .bytes(device_id)
        .bytes(nonce);
    let ad = w.into_vec();
    let mut p = Writer::new();
    p.u8(req.kind).bytes(&req.device_pk).bytes(&req.kem_ek);
    req.ext.encode(&mut p)?;
    let mut out = ad.clone();
    out.extend(seal(key.expose(), nonce, &p.into_secret(), &ad));
    if out.len() > INVITE_MAX {
        return input(InputKind::TooLarge);
    }
    Ok(out)
}

/// Seal the enrollment request for `invite`. Draw order: nonce (24).
pub(crate) fn seal_request_with<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    invite: &Invite,
    req: &EnrollmentRequest,
) -> Result<Vec<u8>> {
    seal_request_with_key(
        &invite.key(),
        &invite.vault_id,
        &invite.device_id,
        req,
        &draw(rng)?,
    )
}

/// Seal the enrollment request the new device writes to `<prefix>enroll/<device_id hex>`.
pub fn seal_request(invite: &Invite, req: &EnrollmentRequest) -> Result<Vec<u8>> {
    seal_request_with(&mut os(), invite, req)
}

pub(crate) fn open_request_with_key(
    bytes: &[u8],
    key: &InviteKey,
    vault_id: &[u8; 16],
    device_id: &[u8; 16],
) -> Result<EnrollmentRequest> {
    if bytes.len() > INVITE_MAX || bytes.len() < REQUEST_PREFIX_LEN {
        return integrity(K::SizeLimit);
    }
    let mut r = Reader::new(&bytes[..REQUEST_PREFIX_LEN]);
    if &r.array::<4>()? != REQ_MAGIC {
        return integrity(K::BadMagic);
    }
    let v = r.u16()?;
    if v != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion(v));
    }
    if r.u16()? != 0 {
        return integrity(K::UnknownFlags);
    }
    if &r.array::<16>()? != vault_id {
        return integrity(K::VaultIdMismatch);
    }
    if &r.array::<16>()? != device_id {
        return integrity(K::ObjectIdMismatch);
    }
    let nonce = r.array()?;
    let plain = open(
        key.expose(),
        &nonce,
        &bytes[REQUEST_PREFIX_LEN..],
        &bytes[..REQUEST_PREFIX_LEN],
    )?;
    let mut r = Reader::new(&plain);
    let kind = r.u8()?;
    let device_pk = r.array()?;
    let kem_ek = r.take(KEM_EK_LEN)?.to_vec();
    let ext = ExtList::decode(&mut r, ExtCtx::Other)?;
    r.finish()?;
    if !(1..=4).contains(&kind) {
        return integrity(K::DeviceKind);
    }
    check_kem_ek(&kem_ek)?;
    Ok(EnrollmentRequest {
        kind,
        device_pk,
        kem_ek,
        ext,
    })
}

/// Open the enrollment request that answers `invite`.
pub fn open_request(invite: &Invite, bytes: &[u8]) -> Result<EnrollmentRequest> {
    open_request_with_key(bytes, &invite.key(), &invite.vault_id, &invite.device_id)
}

/// The comparison code of a request object: 80 bits of SHA-256, as four groups of four.
pub fn comparison_code(request_object: &[u8]) -> String {
    let h = sha256(&[b"vlt/v1/enroll-compare", request_object]);
    let c = crock(&h[..10]);
    format!("{}-{}-{}-{}", &c[0..4], &c[4..8], &c[8..12], &c[12..16])
}

/// Whether a typed comparison code equals the expected one, with the secret key's tolerance for
/// case, `-`, spaces, and `O`, `I`, and `L`.
pub fn comparison_code_matches(typed: &str, expected: &str) -> bool {
    // Both codes are on screen, so an ordinary comparison is fine.
    match (crock_decode(typed, 10), crock_decode(expected, 10)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The vault configuration line: `vlt-vault:1:<vault_id hex>:<region>:<bucket>:<prefix>:<endpoint>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    /// Vault ID.
    pub vault_id: [u8; 16],
    /// Region.
    pub region: String,
    /// Bucket.
    pub bucket: String,
    /// Prefix.
    pub prefix: String,
    /// Endpoint; empty for AWS.
    pub endpoint: String,
}

impl VaultConfig {
    /// Encode, with the vault ID in lowercase hex.
    pub fn to_line(&self) -> Result<String> {
        check_location(
            &self.endpoint,
            &self.region,
            &self.bucket,
            &self.prefix,
            true,
        )?;
        let hex: String = self.vault_id.iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!(
            "vlt-vault:1:{hex}:{}:{}:{}:{}",
            self.region, self.bucket, self.prefix, self.endpoint
        ))
    }

    /// Decode. The vault ID is accepted in either case, because kit lines are typed by hand.
    /// `allow_http` admits a plain `http://` endpoint to a non-loopback host.
    pub fn from_line(line: &str, allow_http: bool) -> Result<VaultConfig> {
        let rest = line
            .trim()
            .strip_prefix("vlt-vault:1:")
            .ok_or(Error::InvalidInput(InputKind::VaultConfig))?;
        let mut it = rest.splitn(5, ':');
        let (Some(hex), Some(region), Some(bucket), Some(prefix), Some(endpoint)) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            return input(InputKind::VaultConfig);
        };
        if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return input(InputKind::VaultConfig);
        }
        let mut vault_id = [0u8; 16];
        for (i, b) in vault_id.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map_err(|_| Error::InvalidInput(InputKind::VaultConfig))?;
        }
        check_location(endpoint, region, bucket, prefix, allow_http)?;
        Ok(VaultConfig {
            vault_id,
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
            endpoint: endpoint.to_owned(),
        })
    }
}
