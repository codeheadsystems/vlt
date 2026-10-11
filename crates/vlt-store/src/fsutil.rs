//! File helpers shared by the local store and the descriptor: owner-only modes, durable
//! temporary files, and directory `fsync`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Temporary files start with this, so a listing never mistakes one for an object.
const TMP_PREFIX: &str = ".tmp-";

pub(crate) fn dir_builder() -> fs::DirBuilder {
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b
}

pub(crate) fn file_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Makes a directory's entries durable. Only Unix can open a directory for `fsync`.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Writes `bytes` to a fresh temporary file in `dir` and `fsync`s it.
pub(crate) fn write_temp(dir: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let mut rnd = [0u8; 16];
    getrandom::fill(&mut rnd).map_err(|_| io::Error::other("random number generator failed"))?;
    let path = dir.join(format!("{TMP_PREFIX}{}", hex::encode(rnd)));
    let mut f = file_options().write(true).create_new(true).open(&path)?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    if let Err(e) = written {
        let _ = fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}
