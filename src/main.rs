mod inject;

fn main() {
    env_logger::init();

    inject::inject("Spotify.exe", "test32.dll").unwrap();
}
