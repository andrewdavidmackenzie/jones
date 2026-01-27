use std::path::PathBuf;

/// parse the command line arguments into the three cases accepted:
/// 1) --example
///    Verify there is an example with that name and then find the compiled binary in ./target
///    depending on --debug or --release switch
/// 2) --examples
///    Generate a Vec of the paths to example binaries in ./target according to --debug or
///    --release switch
/// 3) --bin $path
///    Check that the binary file specified by the --bin option exists and is readable
pub(crate) fn parse_args(args: &[String]) -> Result<Vec<PathBuf>, String> {
    if args.len() < 2 {
        return Err(usage());
    }

    match args[1].as_str() {
        "--example" => parse_example_args(args),
        "--examples" => parse_examples_args(args),
        "--bin" => parse_bin_args(args),
        "--lib" => parse_lib_args(args),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "Usage:\n  \
     jones --example <example_name> --debug|--release\n  \
     jones --examples --debug|--release\n  \
     jones --bin <path_to_binary>
     jones --lib <path_to_lib_object>"
        .to_string()
}

/// Parse --example example_name --debug or --release
fn parse_example_args(args: &[String]) -> Result<Vec<PathBuf>, String> {
    if args.len() != 4 {
        return Err("--example requires an example name and --debug or --release".to_string());
    }

    let example_name = &args[2];
    let build_type = &args[3];

    // Verify the example source exists
    let example_source = PathBuf::from(format!("examples/{}.rs", example_name));
    if !example_source.exists() {
        return Err(format!(
            "Example '{}' not found at {:?}",
            example_name, example_source
        ));
    }

    // Determine the target directory based on the build type
    let target_dir = match build_type.as_str() {
        "--debug" => "target/debug/examples",
        "--release" => "target/release/examples",
        _ => return Err("Expected --debug or --release".to_string()),
    };

    let binary_path = PathBuf::from(format!("{}/{}", target_dir, example_name));
    if !binary_path.exists() {
        return Err(format!(
            "Binary for example '{}' not found at {:?}. Did you build it?",
            example_name, binary_path
        ));
    }

    Ok(vec![binary_path])
}

/// Parse --examples --debug or --release
fn parse_examples_args(args: &[String]) -> Result<Vec<PathBuf>, String> {
    if args.len() != 3 {
        return Err("--examples requires --debug or --release".to_string());
    }

    let build_type = &args[2];

    // Determine the target directory based on the build type
    let target_dir = match build_type.as_str() {
        "--debug" => "target/debug/examples",
        "--release" => "target/release/examples",
        _ => return Err("Expected --debug or --release".to_string()),
    };

    // Get all example source files
    let examples_dir = PathBuf::from("examples");
    if !examples_dir.exists() {
        return Err("examples directory not found".to_string());
    }

    let mut binaries = Vec::new();
    let entries = std::fs::read_dir(&examples_dir)
        .map_err(|e| format!("Failed to read examples directory: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "rs")
            && let Some(stem) = path.file_stem()
        {
            let example_name = stem.to_string_lossy();
            let binary_path = PathBuf::from(format!("{}/{}", target_dir, example_name));

            if binary_path.exists() {
                binaries.push(binary_path);
            }
        }
    }

    if binaries.is_empty() {
        println!("No example binaries found in {}", target_dir);
    } else {
        println!(
            "Found {} binaries found in {}\n",
            binaries.len(),
            target_dir
        );
    }

    Ok(binaries)
}

/// Parse --bin path_to_binary
fn parse_bin_args(args: &[String]) -> Result<Vec<PathBuf>, String> {
    if args.len() != 3 {
        return Err("--bin requires a path to a binary".to_string());
    }

    let binary_path = PathBuf::from(&args[2]);

    // Check that the file exists
    if !binary_path.exists() {
        return Err(format!("Binary not found at {:?}", binary_path));
    }

    // Check that the file is readable by attempting to open it
    std::fs::File::open(&binary_path)
        .map_err(|e| format!("Cannot read binary at {:?}: {}", binary_path, e))?;

    Ok(vec![binary_path])
}

/// Parse --bin path_to_library_object
fn parse_lib_args(args: &[String]) -> Result<Vec<PathBuf>, String> {
    if args.len() != 3 {
        return Err("--lib requires a path to a library object file".to_string());
    }

    let binary_path = PathBuf::from(&args[2]);

    // Check that the file exists
    if !binary_path.exists() {
        return Err(format!(
            "Library shared object not found at {:?}",
            binary_path
        ));
    }

    // Check that the file is readable by attempting to open it
    std::fs::File::open(&binary_path).map_err(|e| {
        format!(
            "Cannot read Library shared object at {:?}: {}",
            binary_path, e
        )
    })?;

    Ok(vec![binary_path])
}
