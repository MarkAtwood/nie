pub mod api;

/// Called by the Flutter engine once before any other FFI call.
///
/// On Android: routes Rust log output to logcat under the tag "nie-ffi".
/// On all platforms: installs the flutter_rust_bridge default executor, which
/// provides the tokio runtime that backs all async FFI functions.
#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("nie-ffi")
            .with_max_level(log::LevelFilter::Info),
    );

    flutter_rust_bridge::setup_default_user_utils();
}
