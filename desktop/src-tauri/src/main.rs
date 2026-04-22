// Prevents a Windows console window from opening alongside the app window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nie_desktop_lib::run();
}
