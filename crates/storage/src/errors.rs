use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Redb error: {0}")]
    Redb(#[from] Box<redb::Error>),

    #[error("Io error in creating DB file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Field not initilized")]
    FieldNotInitilized,

    #[error("DecodeError not found {0}")]
    DecodeError(String),

    #[error("SnappyError not found {0}")]
    SnappyError(#[from] snap::Error),
}

impl From<redb::Error> for StoreError {
    fn from(err: redb::Error) -> Self {
        StoreError::Redb(Box::new(err))
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(err: redb::TransactionError) -> Self {
        StoreError::Redb(Box::new(err.into()))
    }
}

impl From<redb::TableError> for StoreError {
    fn from(err: redb::TableError) -> Self {
        StoreError::Redb(Box::new(err.into()))
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(err: redb::CommitError) -> Self {
        StoreError::Redb(Box::new(err.into()))
    }
}

impl From<redb::StorageError> for StoreError {
    fn from(err: redb::StorageError) -> Self {
        StoreError::Redb(Box::new(err.into()))
    }
}

impl From<redb::DatabaseError> for StoreError {
    fn from(err: redb::DatabaseError) -> Self {
        StoreError::Redb(Box::new(err.into()))
    }
}

impl From<ssz::DecodeError> for StoreError {
    fn from(value: ssz::DecodeError) -> Self {
        StoreError::DecodeError(format!("{value:?}"))
    }
}
