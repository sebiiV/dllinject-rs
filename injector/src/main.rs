mod inject;

fn main() {
    env_logger::init();

    inject::inject("notepad.exe", "dll_rs.dll", true).unwrap();
}
