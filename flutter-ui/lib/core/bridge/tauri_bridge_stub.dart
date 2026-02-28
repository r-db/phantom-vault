/// Stub implementation for non-web platforms
///
/// Mobile platforms use flutter_rust_bridge FFI instead.

bool isTauri() => false;

Future<dynamic> invoke(String command, Map<String, dynamic> args) {
  throw UnsupportedError(
    'Tauri bridge is only available on web platform. '
    'Use flutter_rust_bridge for mobile.',
  );
}
