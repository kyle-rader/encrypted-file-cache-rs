use std::path::PathBuf;
use tokio::fs;

#[cfg(target_os = "windows")]
use windows::{
    core::*, Security::Cryptography::DataProtection::*, Security::Cryptography::*,
    Storage::Streams::*, Win32::System::WinRT::*,
};

#[derive(Debug)]
pub struct EncryptedCache {
    file: PathBuf,
}

impl EncryptedCache {
    pub fn new(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into() }
    }

    #[cfg(target_os = "windows")]
    pub async fn put(&self, data: &str) -> anyhow::Result<()> {
        let provider = DataProtectionProvider::CreateOverloadExplicit("LOCAL=user")?;
        let unprotected =
            CryptographicBuffer::ConvertStringToBinary(data, BinaryStringEncoding::Utf8)?;
        let protected = provider.ProtectAsync(unprotected)?.get()?;
        let protected_bytes = unsafe { as_mut_bytes(&protected)? };
        fs::write(&self.file, protected_bytes).await?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn get(&self) -> anyhow::Result<String> {
        let protected_bytes = std::fs::read(&self.file)?;
        let provider = DataProtectionProvider::CreateOverloadExplicit("LOCAL=user")?;
        let protected = CryptographicBuffer::CreateFromByteArray(&protected_bytes)?;
        let unprotected = provider.UnprotectAsync(protected)?.get()?;
        Ok(
            CryptographicBuffer::ConvertBinaryToString(BinaryStringEncoding::Utf8, unprotected)?
                .to_string(),
        )
    }
}

#[cfg(target_os = "windows")]
unsafe fn as_mut_bytes(buffer: &IBuffer) -> Result<&mut [u8]> {
    let interop = buffer.cast::<IBufferByteAccess>()?;
    let data = interop.Buffer()?;
    Ok(std::slice::from_raw_parts_mut(data, buffer.Length()? as _))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn it_works() {
        use tempfile::tempdir;

        let cache = tempdir().expect("we expected to get a temp dir");
        let cache: PathBuf = [cache.path().to_str().expect("path to_str()"), "test.cache"]
            .iter()
            .collect();
        let cache = EncryptedCache::new(cache);
        let content = "secret_stuff";

        cache.put(content).await.expect("Failed to put the cache!");

        let subject = cache.get().await.unwrap();
        assert_eq!(subject, String::from("secret_stuff"));
    }
}
