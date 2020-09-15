mod inject;

fn main() {
    env_logger::init();
    // We specify full $PATH here so we inherit the CWD of the injected process
    let dll_path = "C:\\Users\\sebiV\\git\\dllinject-rs\\target\\debug\\dll_rs.dll";
    inject::inject("messageboxW.exe", dll_path, true).unwrap();
}
