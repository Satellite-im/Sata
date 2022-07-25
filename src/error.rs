use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Position in array cannot be found")]
    PositionNotFound,
    #[error("Attempted to set encoded on data that has already been initalized.")]
    EncodingSetOutOfOrder,
    #[error("Your Sata is uninitalized, please initalize before attempting.")]
    UnInitalized,
    #[error("You can't decode encrypted data, please decrypt first.")]
    CannotDecodeEncrypted,
    #[error("You can't encode encrypted data, please decrypt first.")]
    AlreadyEncrypted,
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("unknown data store error")]
    Unknown,
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error)
}