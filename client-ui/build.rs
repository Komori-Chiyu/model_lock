fn main() {
    #[cfg(windows)]
    {
        // Embed the app icon into the exe resource (Explorer/taskbar icon).
        // Icon path is relative to this package dir (client-ui/).
        winres::WindowsResource::new()
            .set_icon("../packaging/icon.ico")
            .compile()
            .expect("failed to embed app icon");
    }
}
