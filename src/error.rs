#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("PE error: {0}")]
    PeLite(#[from] pelite::Error),
    #[error("LightGBM error: {0}")]
    LightGBM(#[from] lightgbm::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("{0}")]
    Generic(String),
}
