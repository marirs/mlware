use std::io::Read;


fn load_file(file_name: &str) -> Vec<u8>{
    let mut file = std::fs::File::open(file_name).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    data
}


fn main(){
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3{
        println!("Usage:\n\t{} <model file name> <file to test>", args[0]);
        return;
    }
    let model_file = &args[1];
    let file_to_test = &args[2];
    let bst = lightgbm::Booster::from_file(model_file).unwrap();
    let score = deepmal::predict_sample(&bst, &load_file(&file_to_test)).unwrap();
    println!("{:?}", score[0]);
}
