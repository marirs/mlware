mod error;
mod features;
mod utils;

use std::io::Read;

pub type Result<T> = std::result::Result<T, error::Error>;

fn read_vectorized_features(data_dir: &str) -> Result<(Vec<Vec<f64>>, Vec<f32>)>{
    let mut x_train = vec![];
    let mut y_train = vec![];
    let yfile = std::fs::File::open(format!("{}/{}",data_dir, "y_train.dat"))?;
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
    let xfile = std::fs::File::open(format!("{}/{}",data_dir, "x_train.dat"))?;
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
        if x_str.len() == y_train.len(){
            x_train.push(x_str);
            x_str = vec![];
        }
    }
    Ok((x_train, y_train))
}


pub fn train_model(data_dir: &str, params: &serde_json::Value) -> Result<lightgbm::Booster> {
    let mut p = params.clone();
    p["application"] = serde_json::Value::String("binary".to_string());
    let (x_train, y_train) = read_vectorized_features(data_dir)?;
//    train_rows = (y_train != -1)

    let lgbm_dataset = lightgbm::Dataset::from_mat(x_train, y_train)?;
    let lgbm_model = lightgbm::Booster::train(lgbm_dataset, &p)?;
    Ok(lgbm_model)
}


pub fn predict_sample(lgbm_model: &lightgbm::Booster, file_data: &[u8]) -> Result<Vec<f64>>{
    let extractor = features::PeFeaturesExtractor::new()?;
    let features = extractor.feature_vector(file_data)?;
    Ok(lgbm_model.predict(vec![features])?[0].clone())
}
