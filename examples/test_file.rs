fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage:\n\t{} <model file name> <file to test>", args[0]);
        return;
    }
    let model_file = &args[1];
    let file_to_test = &args[2];
    let score = deepmal::predict(model_file, file_to_test).unwrap();
    let label = if score[0] < 0.15 {
        "Benign"
    } else if score[0] < 0.6 {
        "Suspicious"
    } else {
        "Dangerous"
    };
    println!("Type: {}", label);
}
