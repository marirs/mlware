mod error;
mod features;
mod utils;
use std::{io::Read, path::Path};

pub type Result<T> = std::result::Result<T, error::Error>;

fn read_vectorized_features(data_dir: &str) -> Result<(Vec<Vec<f64>>, Vec<f32>)> {
    let mut x_train = vec![];
    let mut y_train = vec![];
    let yfile = std::fs::File::open(format!("{}/{}", data_dir, "y_train.dat"))?;
    let mut yreader = std::io::BufReader::new(yfile);
    let mut buffer = [0u8; 4];
    loop {
        if let Err(e) = yreader.read_exact(&mut buffer) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e.into());
        }
        y_train.push(f32::from_le_bytes(buffer));
    }
    let xfile = std::fs::File::open(format!("{}/{}", data_dir, "x_train.dat"))?;
    let mut xreader = std::io::BufReader::new(xfile);
    let mut buffer = [0u8; 4];
    let mut x_str = vec![];
    loop {
        if let Err(e) = xreader.read_exact(&mut buffer) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e.into());
        }
        x_str.push(f32::from_le_bytes(buffer) as f64);
        if x_str.len() == y_train.len() {
            x_train.push(x_str);
            x_str = vec![];
        }
    }
    Ok((x_train, y_train))
}

pub fn train_model(data_dir: &str, params: &serde_json::Value) -> Result<lightgbm3::Booster> {
    //! Train a model from the given dataset
    //!
    let mut p = params.clone();
    p["application"] = serde_json::Value::String("binary".to_string());
    let (x_train, y_train) = read_vectorized_features(data_dir)?;
    //    train_rows = (y_train != -1)

    let lgbm_dataset = lightgbm3::Dataset::from_vec_of_vec(x_train, y_train, true)?;
    let lgbm_model = lightgbm3::Booster::train(lgbm_dataset, &p)?;
    Ok(lgbm_model)
}

pub fn predict<P: AsRef<Path>>(model_file: P, file: P) -> Result<Vec<f64>> {
    //! Predict a given PE executable to see if its a malware, suspicious or benign file.
    //! ## Example
    //! ```rust
    //! use mlware::predict;
    //!
    //! let score = predict("rs-model/model.txt", "data/Demo64.dll").unwrap();
    //! println!("{:?}", score[0]);
    //! ```
    let lgbm_model = lightgbm3::Booster::from_file(model_file.as_ref().to_str().unwrap())?;
    let extractor = features::PeFeaturesExtractor::new()?;
    let features = extractor.feature_vector(&utils::load_file(file))?;
    Ok(lgbm_model.predict(&features, features.len() as i32, false)?)
}
