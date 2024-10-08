extern crate serde_json;

fn main() -> mlware::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!(
            "Usage:\n\t{} <train data path> <file to save model>",
            args[0]
        );
        return Ok(());
    }
    let train_data_path = &args[1];
    let model_file_name = &args[2];
    let model = mlware::train_model(train_data_path, &serde_json::json! {{}}).unwrap();
    model.save_file(model_file_name)?;
    println!("Done");
    Ok(())
}
