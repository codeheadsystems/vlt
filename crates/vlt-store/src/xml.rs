//! Parsing of the S3 XML bodies vlt reads: error responses, bucket settings, and listings. The
//! bodies are read into a small element tree with namespaces stripped; every body is size-capped
//! before it gets here.

use crate::error::{StoreError, sanitise_code};
use crate::probe::{Lifecycle, ObjectLock, RetentionMode, Versioning};
use quick_xml::Reader;
use quick_xml::events::Event;

/// Nesting deeper than any S3 response needs is refused.
const MAX_DEPTH: usize = 16;

const MALFORMED: StoreError = StoreError::Protocol {
    what: "malformed XML",
};

/// One element: its local name, its text content, and its child elements.
#[derive(Debug, Default)]
pub(crate) struct Element {
    pub(crate) name: String,
    pub(crate) text: String,
    pub(crate) children: Vec<Element>,
}

impl Element {
    pub(crate) fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub(crate) fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub(crate) fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

fn entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => return None,
    })
}

/// Parses a document into its root element.
pub(crate) fn parse(body: &[u8]) -> Result<Element, StoreError> {
    let mut reader = Reader::from_reader(body);
    let mut stack: Vec<Element> = Vec::new();
    loop {
        let event = reader.read_event().map_err(|_| MALFORMED)?;
        match event {
            Event::Start(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(MALFORMED);
                }
                let name =
                    String::from_utf8(e.local_name().as_ref().to_vec()).map_err(|_| MALFORMED)?;
                stack.push(Element {
                    name,
                    ..Element::default()
                });
            }
            Event::Empty(e) => {
                let name =
                    String::from_utf8(e.local_name().as_ref().to_vec()).map_err(|_| MALFORMED)?;
                let el = Element {
                    name,
                    ..Element::default()
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Ok(el),
                }
            }
            Event::End(_) => {
                let el = stack.pop().ok_or(MALFORMED)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Ok(el),
                }
            }
            Event::Text(t) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&t.decode().map_err(|_| MALFORMED)?);
                }
            }
            Event::CData(t) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&t.decode().map_err(|_| MALFORMED)?);
                }
            }
            Event::GeneralRef(r) => {
                let c = match r.resolve_char_ref().map_err(|_| MALFORMED)? {
                    Some(c) => c,
                    None => entity(&r.decode().map_err(|_| MALFORMED)?).ok_or(MALFORMED)?,
                };
                if let Some(top) = stack.last_mut() {
                    top.text.push(c);
                }
            }
            Event::Eof => return Err(MALFORMED),
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::DocType(_) => {}
        }
    }
}

/// The S3 error code in an error body, if the body is an `<Error>` document with a sane code.
pub(crate) fn error_code(body: &[u8]) -> Option<String> {
    let root = parse(body).ok()?;
    if root.name != "Error" {
        return None;
    }
    sanitise_code(root.text_of("Code")?.trim())
}

/// `GetBucketVersioning`.
pub(crate) fn versioning(body: &[u8]) -> Result<Versioning, StoreError> {
    let root = parse(body)?;
    if root.name != "VersioningConfiguration" {
        return Err(MALFORMED);
    }
    match root.text_of("Status").map(str::trim) {
        Some("Enabled") => Ok(Versioning::Enabled),
        Some("Suspended") => Ok(Versioning::Suspended),
        None | Some("") => Ok(Versioning::Off),
        Some(_) => Err(StoreError::Protocol {
            what: "unknown versioning status",
        }),
    }
}

/// `GetObjectLockConfiguration`.
pub(crate) fn object_lock(body: &[u8]) -> Result<ObjectLock, StoreError> {
    let root = parse(body)?;
    if root.name != "ObjectLockConfiguration" {
        return Err(MALFORMED);
    }
    let enabled = root.text_of("ObjectLockEnabled").map(str::trim) == Some("Enabled");
    let mode = root
        .child("Rule")
        .and_then(|r| r.child("DefaultRetention"))
        .and_then(|d| d.text_of("Mode"))
        .map(str::trim);
    let default_mode = match mode {
        None => None,
        Some("GOVERNANCE") => Some(RetentionMode::Governance),
        Some("COMPLIANCE") => Some(RetentionMode::Compliance),
        Some(_) => {
            return Err(StoreError::Protocol {
                what: "unknown retention mode",
            });
        }
    };
    Ok(ObjectLock {
        enabled,
        default_mode,
    })
}

/// The prefix a lifecycle rule filters on, or `None` when the rule does not apply to vlt's objects
/// (it requires a tag, and vlt never tags). Size filters are ignored, which can only make a rule
/// look like it applies.
fn rule_prefix(rule: &Element) -> Option<String> {
    let Some(filter) = rule.child("Filter") else {
        // The legacy form puts `Prefix` directly in the rule.
        return Some(rule.text_of("Prefix").unwrap_or("").to_owned());
    };
    let scope = filter.child("And").unwrap_or(filter);
    if scope.child("Tag").is_some() {
        return None;
    }
    Some(scope.text_of("Prefix").unwrap_or("").to_owned())
}

/// `GetBucketLifecycleConfiguration`, reduced to the shortest noncurrent expiry that covers each
/// of the two full keys.
pub(crate) fn lifecycle(
    body: &[u8],
    header_key: &str,
    index_key: &str,
) -> Result<Lifecycle, StoreError> {
    let root = parse(body)?;
    if root.name != "LifecycleConfiguration" {
        return Err(MALFORMED);
    }
    let mut out = Lifecycle::default();
    for rule in root.children("Rule") {
        if rule.text_of("Status").map(str::trim) != Some("Enabled") {
            continue;
        }
        let Some(days) = rule
            .child("NoncurrentVersionExpiration")
            .and_then(|n| n.text_of("NoncurrentDays"))
        else {
            continue;
        };
        let days: u32 = days.trim().parse().map_err(|_| MALFORMED)?;
        let Some(prefix) = rule_prefix(rule) else {
            continue;
        };
        for (key, slot) in [
            (header_key, &mut out.header_noncurrent_days),
            (index_key, &mut out.index_noncurrent_days),
        ] {
            if key.starts_with(&prefix) {
                *slot = Some(slot.map_or(days, |d| d.min(days)));
            }
        }
    }
    Ok(out)
}

fn truncated(root: &Element) -> bool {
    root.text_of("IsTruncated").map(str::trim) == Some("true")
}

fn size(el: &Element) -> Result<u64, StoreError> {
    el.text_of("Size")
        .unwrap_or("0")
        .trim()
        .parse()
        .map_err(|_| MALFORMED)
}

/// One page of `ListObjectsV2`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ObjectsPage {
    /// Bucket-absolute keys and sizes.
    pub(crate) objects: Vec<(String, u64)>,
    /// The continuation token for the next page, when the listing is truncated.
    pub(crate) next: Option<String>,
}

/// `ListObjectsV2`.
pub(crate) fn objects_page(body: &[u8]) -> Result<ObjectsPage, StoreError> {
    let root = parse(body)?;
    if root.name != "ListBucketResult" {
        return Err(MALFORMED);
    }
    let objects = root
        .children("Contents")
        .map(|c| Ok((c.text_of("Key").ok_or(MALFORMED)?.to_owned(), size(c)?)))
        .collect::<Result<_, StoreError>>()?;
    let next = if truncated(&root) {
        let token = root.text_of("NextContinuationToken").unwrap_or("");
        if token.is_empty() {
            return Err(StoreError::Protocol {
                what: "truncated listing without a continuation token",
            });
        }
        Some(token.to_owned())
    } else {
        None
    };
    Ok(ObjectsPage { objects, next })
}

/// One page of `ListObjectVersions`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VersionsPage {
    /// Bucket-absolute keys and sizes of versions and delete markers (size 0), in listing order.
    pub(crate) entries: Vec<(String, u64)>,
    /// The key and version ID markers for the next page, when the listing is truncated.
    pub(crate) next: Option<(String, String)>,
}

/// `ListObjectVersions`.
pub(crate) fn versions_page(body: &[u8]) -> Result<VersionsPage, StoreError> {
    let root = parse(body)?;
    if root.name != "ListVersionsResult" {
        return Err(MALFORMED);
    }
    let mut entries = Vec::new();
    for el in &root.children {
        let sized = match el.name.as_str() {
            "Version" => true,
            "DeleteMarker" => false,
            _ => continue,
        };
        let key = el.text_of("Key").ok_or(MALFORMED)?.to_owned();
        entries.push((key, if sized { size(el)? } else { 0 }));
    }
    let next = if truncated(&root) {
        let key = root.text_of("NextKeyMarker").unwrap_or("");
        let version = root.text_of("NextVersionIdMarker").unwrap_or("");
        if key.is_empty() {
            return Err(StoreError::Protocol {
                what: "truncated listing without a key marker",
            });
        }
        Some((key.to_owned(), version.to_owned()))
    } else {
        None
    };
    Ok(VersionsPage { entries, next })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message>
<Key>vlt/e/00</Key><RequestId>X</RequestId></Error>"#;
        assert_eq!(error_code(body).as_deref(), Some("NoSuchKey"));
        assert_eq!(error_code(b"<Error><Code>a b</Code></Error>"), None);
        assert_eq!(error_code(b"<Other><Code>X</Code></Other>"), None);
        assert_eq!(error_code(b"not xml at all <"), None);
        assert_eq!(error_code(b""), None);
    }

    #[test]
    fn versioning_states() {
        // RustFS 1.0.1 answers a never-versioned bucket with an empty configuration.
        let off = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></VersioningConfiguration>"#;
        assert_eq!(versioning(off).unwrap(), Versioning::Off);
        let off_empty =
            br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#;
        assert_eq!(versioning(off_empty).unwrap(), Versioning::Off);
        let on = br#"<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#;
        assert_eq!(versioning(on).unwrap(), Versioning::Enabled);
        let susp = b"<VersioningConfiguration><Status>Suspended</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>";
        assert_eq!(versioning(susp).unwrap(), Versioning::Suspended);
        assert!(
            versioning(
                b"<VersioningConfiguration><Status>Maybe</Status></VersioningConfiguration>"
            )
            .is_err()
        );
        assert!(versioning(b"<Error/>").is_err());
    }

    #[test]
    fn object_lock_configurations() {
        let on = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
        assert_eq!(
            object_lock(on).unwrap(),
            ObjectLock {
                enabled: true,
                default_mode: None
            }
        );
        let gov = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Days>365</Days><Mode>GOVERNANCE</Mode></DefaultRetention></Rule></ObjectLockConfiguration>";
        assert_eq!(
            object_lock(gov).unwrap(),
            ObjectLock {
                enabled: true,
                default_mode: Some(RetentionMode::Governance)
            }
        );
        let comp = br#"<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>1</Years></DefaultRetention></Rule></ObjectLockConfiguration>"#;
        assert_eq!(
            object_lock(comp).unwrap().default_mode,
            Some(RetentionMode::Compliance)
        );
    }

    const LC: &[u8] = br#"<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Rule><ID>vlt-header</ID><Filter><Prefix>vlt/header</Prefix></Filter><Status>Enabled</Status>
    <NoncurrentVersionExpiration><NoncurrentDays>365</NoncurrentDays></NoncurrentVersionExpiration></Rule>
  <Rule><ID>vlt-index</ID><Filter><Prefix>vlt/index</Prefix></Filter><Status>Enabled</Status>
    <NoncurrentVersionExpiration><NoncurrentDays>365</NoncurrentDays></NoncurrentVersionExpiration></Rule>
</LifecycleConfiguration>"#;

    #[test]
    fn lifecycle_rules_from_the_setup_script() {
        assert_eq!(
            lifecycle(LC, "vlt/header", "vlt/index").unwrap(),
            Lifecycle {
                header_noncurrent_days: Some(365),
                index_noncurrent_days: Some(365)
            }
        );
        // Another prefix: neither rule applies.
        assert_eq!(
            lifecycle(LC, "other/header", "other/index").unwrap(),
            Lifecycle::default()
        );
    }

    #[test]
    fn lifecycle_takes_the_shortest_applicable_rule() {
        let body = br#"<LifecycleConfiguration>
  <Rule><Filter><Prefix>vlt/</Prefix></Filter><Status>Enabled</Status>
    <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration></Rule>
  <Rule><Filter><Prefix>vlt/header</Prefix></Filter><Status>Enabled</Status>
    <NoncurrentVersionExpiration><NoncurrentDays>365</NoncurrentDays></NoncurrentVersionExpiration></Rule>
  <Rule><Filter></Filter><Status>Disabled</Status>
    <NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>
  <Rule><Filter><And><Prefix>vlt/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter>
    <Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays></NoncurrentVersionExpiration></Rule>
  <Rule><Filter><And><Prefix>vlt/ind</Prefix><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan></And></Filter>
    <Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>20</NoncurrentDays></NoncurrentVersionExpiration></Rule>
  <Rule><Prefix></Prefix><Status>Enabled</Status><Expiration><Days>5</Days></Expiration></Rule>
</LifecycleConfiguration>"#;
        assert_eq!(
            lifecycle(body, "vlt/header", "vlt/index").unwrap(),
            Lifecycle {
                header_noncurrent_days: Some(30),
                index_noncurrent_days: Some(20)
            }
        );
        let legacy = b"<LifecycleConfiguration><Rule><Prefix>vlt/</Prefix><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>";
        assert_eq!(
            lifecycle(legacy, "vlt/header", "vlt/index").unwrap(),
            Lifecycle {
                header_noncurrent_days: Some(7),
                index_noncurrent_days: Some(7)
            }
        );
    }

    #[test]
    fn list_objects_v2_pages() {
        let page1 = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>vlt/e/</Prefix>
<KeyCount>2</KeyCount><MaxKeys>2</MaxKeys><IsTruncated>true</IsTruncated>
<Contents><Key>vlt/e/00</Key><Size>10</Size><ETag>&quot;abc&quot;</ETag></Contents>
<Contents><Key>vlt/e/01</Key><Size>20</Size></Contents>
<NextContinuationToken>tok/en+1=</NextContinuationToken></ListBucketResult>"#;
        assert_eq!(
            objects_page(page1).unwrap(),
            ObjectsPage {
                objects: vec![("vlt/e/00".into(), 10), ("vlt/e/01".into(), 20)],
                next: Some("tok/en+1=".into())
            }
        );
        let last = b"<ListBucketResult><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>";
        assert_eq!(
            objects_page(last).unwrap(),
            ObjectsPage {
                objects: vec![],
                next: None
            }
        );
        let broken = b"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>";
        assert!(objects_page(broken).is_err());
    }

    #[test]
    fn escaped_keys_are_unescaped() {
        let body = b"<ListBucketResult><Contents><Key>a&amp;b&#47;c&lt;</Key><Size>1</Size></Contents></ListBucketResult>";
        assert_eq!(objects_page(body).unwrap().objects[0].0, "a&b/c<");
    }

    #[test]
    fn list_object_versions_pages() {
        // As RustFS 1.0.1 answers `?versions&max-keys=1` on a versioned bucket.
        let body = br#"<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name>
<IsTruncated>true</IsTruncated><NextKeyMarker>vlt/header[rustfs_cache:v2,x]</NextKeyMarker>
<NextVersionIdMarker>3f2a</NextVersionIdMarker>
<Version><Key>vlt/header</Key><VersionId>3f2a</VersionId><IsLatest>true</IsLatest><Size>100</Size></Version>
<DeleteMarker><Key>vlt/e/00</Key><VersionId>1</VersionId></DeleteMarker>
<Version><Key>vlt/index</Key><VersionId>null</VersionId><Size>7</Size></Version>
</ListVersionsResult>"#;
        assert_eq!(
            versions_page(body).unwrap(),
            VersionsPage {
                entries: vec![
                    ("vlt/header".into(), 100),
                    ("vlt/e/00".into(), 0),
                    ("vlt/index".into(), 7)
                ],
                next: Some(("vlt/header[rustfs_cache:v2,x]".into(), "3f2a".into()))
            }
        );
        let empty = br#"<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated></ListVersionsResult>"#;
        assert_eq!(
            versions_page(empty).unwrap(),
            VersionsPage {
                entries: vec![],
                next: None
            }
        );
    }

    #[test]
    fn malformed_documents() {
        assert!(parse(b"<a><b></a>").is_err());
        assert!(parse(b"<a>").is_err());
        assert!(parse(b"<a>&bogus;</a>").is_err());
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        assert!(parse(deep.as_bytes()).is_err());
        assert!(
            objects_page(
                b"<ListBucketResult><Contents><Size>1</Size></Contents></ListBucketResult>"
            )
            .is_err()
        );
        assert!(objects_page(b"<ListBucketResult><Contents><Key>k</Key><Size>-1</Size></Contents></ListBucketResult>").is_err());
    }
}
