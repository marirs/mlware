#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("regex error")]
    UtfError(#[from] regex::Error),
    #[error("pelite error")]
    PeLiteError(#[from] pelite::Error),
    #[error("litegbm error")]
    LightGBMError(#[from] lightgbm::Error),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("utf8 error")]
    Utf8Error(#[from] std::str::Utf8Error)
}
