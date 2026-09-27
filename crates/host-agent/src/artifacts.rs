//! Moves template and snapshot files to and from S3 through presigned URLs
//! the control plane hands out, so hosts never hold S3 credentials and can
//! only touch the objects they were given.
//!
//! Files are zstd-compressed before upload and hashed (SHA-256 of the stored
//! bytes). Downloads are verified before use and decompressed sparsely.

use std::io::SeekFrom;
use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

use crate::api_types::{ArtifactRef, UploadTarget, UploadedArtifact, UploadedPart};

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("transfer failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("storage returned HTTP {0}")]
    Status(u16),
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("compressed file of {size} bytes needs more than the {parts} parts provided")]
    TooManyParts { size: u64, parts: usize },
    #[error("storage returned no ETag for part {0}")]
    MissingEtag(u32),
}

#[derive(Clone)]
pub struct Transfer {
    http: reqwest::Client,
}

impl Default for Transfer {
    fn default() -> Self {
        Self::new()
    }
}

impl Transfer {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .build()
            .expect("static client configuration");
        Self { http }
    }

    /// Compresses `src` next to itself, uploads it and removes the compressed copy.
    pub async fn upload(
        &self,
        src: &Path,
        target: &UploadTarget,
    ) -> Result<UploadedArtifact, ArtifactError> {
        let compressed = src.with_extension("zst.upload");
        let (sha256, size) = compress_file(src, &compressed).await?;
        let result = self.upload_compressed(&compressed, size, target).await;
        let _ = tokio::fs::remove_file(&compressed).await;
        let parts = result?;
        Ok(UploadedArtifact {
            sha256,
            size,
            parts,
        })
    }

    async fn upload_compressed(
        &self,
        path: &Path,
        size: u64,
        target: &UploadTarget,
    ) -> Result<Vec<UploadedPart>, ArtifactError> {
        match target {
            UploadTarget::Put { url } => {
                let body = tokio::fs::read(path).await?;
                self.put(url, body).await?;
                Ok(Vec::new())
            }
            UploadTarget::Multipart {
                part_size,
                part_urls,
            } => {
                let part_size = (*part_size).max(5 * 1024 * 1024);
                let needed = size.div_ceil(part_size).max(1) as usize;
                if needed > part_urls.len() {
                    return Err(ArtifactError::TooManyParts {
                        size,
                        parts: part_urls.len(),
                    });
                }
                let mut file = tokio::fs::File::open(path).await?;
                let mut parts = Vec::with_capacity(needed);
                for (i, url) in part_urls.iter().take(needed).enumerate() {
                    let offset = i as u64 * part_size;
                    let len = part_size.min(size - offset) as usize;
                    let mut buf = vec![0u8; len];
                    file.seek(SeekFrom::Start(offset)).await?;
                    file.read_exact(&mut buf).await?;
                    let number = i as u32 + 1;
                    let etag = self
                        .put(url, buf)
                        .await?
                        .ok_or(ArtifactError::MissingEtag(number))?;
                    parts.push(UploadedPart {
                        part_number: number,
                        etag,
                    });
                }
                Ok(parts)
            }
        }
    }

    async fn put(&self, url: &str, body: Vec<u8>) -> Result<Option<String>, ArtifactError> {
        let mut last = None;
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(attempt))).await;
            }
            match self
                .http
                .put(url)
                .header("content-length", body.len())
                .body(body.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(resp
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned));
                }
                Ok(resp) if resp.status().is_server_error() => {
                    last = Some(ArtifactError::Status(resp.status().as_u16()))
                }
                Ok(resp) => return Err(ArtifactError::Status(resp.status().as_u16())),
                Err(e) => last = Some(ArtifactError::Http(e)),
            }
        }
        Err(last.expect("at least one attempt"))
    }

    /// Downloads, verifies and decompresses an artifact to `dest`.
    pub async fn download(&self, artifact: &ArtifactRef, dest: &Path) -> Result<(), ArtifactError> {
        let compressed = dest.with_extension("zst.download");
        let result = async {
            let resp = self.http.get(&artifact.url).send().await?;
            if !resp.status().is_success() {
                return Err(ArtifactError::Status(resp.status().as_u16()));
            }
            let mut file = tokio::fs::File::create(&compressed).await?;
            let mut hasher = Sha256::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            let actual = hex::encode(hasher.finalize());
            if !actual.eq_ignore_ascii_case(&artifact.sha256) {
                return Err(ArtifactError::HashMismatch {
                    expected: artifact.sha256.clone(),
                    actual,
                });
            }
            decompress_sparse(&compressed, dest).await
        }
        .await;
        let _ = tokio::fs::remove_file(&compressed).await;
        result
    }
}

/// zstd-compresses `src` into `dst`; returns the SHA-256 and size of `dst`.
pub async fn compress_file(src: &Path, dst: &Path) -> Result<(String, u64), ArtifactError> {
    let input = BufReader::new(tokio::fs::File::open(src).await?);
    let mut encoder = async_compression::tokio::bufread::ZstdEncoder::with_quality(
        input,
        async_compression::Level::Precise(3),
    );
    let mut out = tokio::fs::File::create(dst).await?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = encoder.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).await?;
        size += n as u64;
    }
    out.flush().await?;
    Ok((hex::encode(hasher.finalize()), size))
}

/// Decompresses a zstd file, seeking over all-zero blocks so disk images
/// stay sparse.
pub async fn decompress_sparse(src: &Path, dst: &Path) -> Result<(), ArtifactError> {
    const BLOCK: usize = 64 * 1024;
    let input = BufReader::new(tokio::fs::File::open(src).await?);
    let mut decoder = async_compression::tokio::bufread::ZstdDecoder::new(input);
    let mut out = tokio::fs::File::create(dst).await?;
    let mut buf = vec![0u8; BLOCK];
    let mut len = 0u64;
    loop {
        let mut filled = 0;
        while filled < BLOCK {
            let n = decoder.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        if buf[..filled].iter().all(|&b| b == 0) {
            out.seek(SeekFrom::Current(filled as i64)).await?;
        } else {
            out.write_all(&buf[..filled]).await?;
        }
        len += filled as u64;
        if filled < BLOCK {
            break;
        }
    }
    out.set_len(len).await?;
    out.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::{extract::Path as AxPath, http::HeaderMap, routing::put, Router};

    #[tokio::test]
    async fn round_trips_sparse_files() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("disk.img");
        let mut data = vec![0u8; 3 * 64 * 1024 + 17];
        data[70_000] = 7;
        data[3 * 64 * 1024 + 5] = 9;
        tokio::fs::write(&src, &data).await.unwrap();
        let zst = dir.path().join("disk.zst");
        let (sha, size) = compress_file(&src, &zst).await.unwrap();
        assert!(size < data.len() as u64);
        assert_eq!(sha.len(), 64);
        let out = dir.path().join("out.img");
        decompress_sparse(&zst, &out).await.unwrap();
        assert_eq!(tokio::fs::read(&out).await.unwrap(), data);
    }

    #[tokio::test]
    async fn uploads_multipart_and_verifies_downloads() {
        let received: Arc<Mutex<Vec<(u32, usize)>>> = Arc::default();
        let blobs: Arc<Mutex<Vec<u8>>> = Arc::default();
        let r2 = received.clone();
        let b2 = blobs.clone();
        let app = Router::new()
            .route(
                "/part/{n}",
                put(move |AxPath(n): AxPath<u32>, body: axum::body::Bytes| {
                    let r = r2.clone();
                    let b = b2.clone();
                    async move {
                        r.lock().unwrap().push((n, body.len()));
                        b.lock().unwrap().extend_from_slice(&body);
                        let mut h = HeaderMap::new();
                        h.insert("etag", format!("\"etag-{n}\"").parse().unwrap());
                        (h, "")
                    }
                }),
            )
            .route(
                "/blob",
                axum::routing::get({
                    let b = blobs.clone();
                    move || {
                        let b = b.clone();
                        async move { b.lock().unwrap().clone() }
                    }
                }),
            )
            .layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("mem");
        // Incompressible data so it needs two 5 MiB parts.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let data: Vec<u8> = (0..6 * 1024 * 1024)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect();
        tokio::fs::write(&src, &data).await.unwrap();
        let t = Transfer {
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        let target = UploadTarget::Multipart {
            part_size: 5 * 1024 * 1024,
            part_urls: (1..=3).map(|n| format!("http://{addr}/part/{n}")).collect(),
        };
        let up = t.upload(&src, &target).await.unwrap();
        assert_eq!(up.parts.len(), 2);
        assert_eq!(up.parts[1].etag, "\"etag-2\"");
        assert_eq!(received.lock().unwrap()[0], (1, 5 * 1024 * 1024));
        assert!(
            !dir.path().join("mem.zst.upload").exists(),
            "temporary file removed"
        );

        let dest = dir.path().join("restored");
        let good = ArtifactRef {
            url: format!("http://{addr}/blob"),
            sha256: up.sha256.clone(),
            size: up.size,
        };
        t.download(&good, &dest).await.unwrap();
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), data);

        let bad = ArtifactRef {
            sha256: "00".repeat(32),
            ..good
        };
        assert!(matches!(
            t.download(&bad, &dest).await,
            Err(ArtifactError::HashMismatch { .. })
        ));

        let too_few = UploadTarget::Multipart {
            part_size: 5 * 1024 * 1024,
            part_urls: vec![format!("http://{addr}/part/1")],
        };
        assert!(matches!(
            t.upload(&src, &too_few).await,
            Err(ArtifactError::TooManyParts { .. })
        ));
    }
}
