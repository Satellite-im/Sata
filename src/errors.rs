use thiserror::Error;

#[derive(Error, Debug)]
pub enum SataError {
    #[error("Attempted to set encoded on data that has already been initalized.")]
    EncodingSetOutOfOrder,
    #[error("Cannot encode data that isn't in a `Decoded` state.")]
    NotDecoded,
    #[error("Cannot decode data that isn't in a `Encoded` state.")]
    NotEncoded,
    #[error("Your Sata is uninitalized, please initalize before attempting.")]
    UnInitalized,
    #[error("You can't decode encrypted data, please decrypt first.")]
    CannotDecodeEncrypted,
    #[error("You can't encode encrypted data, please decrypt first.")]
    CannotEncodeEncrypted,
    #[error("Your Sata is already encrytped, cannot encrypt twice.")]
    AlreadyEncrypted,
    #[error("unknown data store error")]
    Unknown,
}