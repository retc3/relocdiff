use crate::{Error, Function, PeImage, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAGIC: &[u8; 4] = b"RDXI";
const FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
/// A compact, reusable cache of recovered functions from one PE image.
pub struct AnalysisIndex {
    image_base: u64,
    size_of_image: u32,
    functions: Vec<Function>,
}

impl AnalysisIndex {
    /// Build an index by recovering all functions from a parsed image.
    pub fn from_image(image: &PeImage) -> Self {
        Self {
            image_base: image.image_base(),
            size_of_image: image.size_of_image(),
            functions: image.recoverable_functions().collect(),
        }
    }

    /// Return the preferred image base captured in the index.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Return the mapped image size captured in the index.
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Return all recovered functions in address order.
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// Return the function containing a virtual address.
    pub fn function_at_va(&self, va: u64) -> Result<Function> {
        let rva = va
            .checked_sub(self.image_base)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Error::OutsideCode(va))?;
        self.function_at_rva(rva)
    }

    /// Return the function containing an RVA.
    pub fn function_at_rva(&self, rva: u32) -> Result<Function> {
        if rva >= self.size_of_image {
            return Err(Error::OutsideCode(self.image_base + u64::from(rva)));
        }
        self.functions
            .iter()
            .find(|function| {
                rva >= function.rva && rva.saturating_sub(function.rva) < function.byte_size
            })
            .cloned()
            .ok_or(Error::NoFunction(self.image_base + u64::from(rva)))
    }

    /// Serialize this index to a versioned compact binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let payload = postcard::to_allocvec(self)
            .map_err(|error| Error::InvalidIndex(format!("cannot encode index: {error}")))?;
        let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Deserialize an index from the versioned compact binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + 1 || &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::InvalidIndex("missing RDXI header".into()));
        }
        if bytes[MAGIC.len()] != FORMAT_VERSION {
            return Err(Error::InvalidIndex(format!(
                "unsupported format version {}",
                bytes[MAGIC.len()]
            )));
        }
        let (index, remaining) = postcard::take_from_bytes(&bytes[MAGIC.len() + 1..])
            .map_err(|error| Error::InvalidIndex(format!("cannot decode index: {error}")))?;
        if !remaining.is_empty() {
            return Err(Error::InvalidIndex("trailing bytes".into()));
        }
        Ok(index)
    }

    /// Write this index to a file.
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        std::fs::write(path, self.to_bytes()?).map_err(|error| {
            Error::InvalidIndex(format!("cannot write {}: {error}", path.display()))
        })
    }

    /// Read an index from a file.
    pub fn read_from(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|error| {
            Error::InvalidIndex(format!("cannot read {}: {error}", path.display()))
        })?;
        Self::from_bytes(&bytes)
    }
}
