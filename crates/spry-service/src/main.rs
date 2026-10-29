#![forbid(unsafe_code)]

fn main() {
    // Only `spry-node portmap ...` reads arguments; the service itself is
    // configured by its environment, as before.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|first| first == "portmap") {
        std::process::exit(spry_service::portmap::command(&args[1..]));
    }
    spry_service::main_with_assets(spry_service::UiAssets::STANDALONE);
}
