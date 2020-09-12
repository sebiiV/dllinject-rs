mod inject;

fn main() {
    env_logger::init();

    inject::inject("notepad.exe", "wmp.dll", false).unwrap();
}
