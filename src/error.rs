use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Data is already initialized")]
    InitializedData,
    #[error("Data is invalid")]
    InvalidData,
    #[error("Position in array cannot be found")]
    PositionNotFound,
    #[error("Attempted to set encoded on data that has already been initalized.")]
    EncodingSetOutOfOrder,
    #[error("You can't decode encrypted data, please decrypt first.")]
    CannotDecodeEncrypted,
    #[error("Data is already encrypted")]
    AlreadyEncrypted,
    #[error("Private keys required for encryption")]
    PrivateKeyRequired,
    #[error("Recipient already exist")]
    RecipientExist,
    #[error("Recipient doesnt exist")]
    RecipientDoesntExist,
    #[error("Recipient required")]
    RecipientRequired,
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("unknown data store error")]
    Unknown,
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
    #[error(transparent)]
    CidError(#[from] libipld::cid::Error),
    #[error(transparent)]
    IpldCodecError(#[from] libipld::error::UnsupportedCodec)
}