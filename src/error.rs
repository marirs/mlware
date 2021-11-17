#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Regex error: {0}")]
    UtfError(#[from] regex::Error),
    #[error("PE error: {0}")]
    PeLiteError(#[from] pelite::Error),
    #[error("LightGBM error: {0}")]
    LightGBMError(#[from] lightgbm::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("UTF8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("{0}")]
    Generic(String),
}
