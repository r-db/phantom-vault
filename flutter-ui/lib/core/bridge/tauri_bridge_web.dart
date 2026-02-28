import 'dart:async';
import 'dart:js_interop';

/// Web implementation using JavaScript interop for Tauri
///
/// Calls window.__TAURI__.core.invoke() to communicate with Rust backend.

/// Check if running inside Tauri
bool isTauri() {
  return _checkTauriExists();
}

/// Invoke a Tauri command
Future<dynamic> invoke(String command, Map<String, dynamic> args) async {
  if (!isTauri()) {
    throw StateError('Not running in Tauri environment');
  }

  try {
    // Convert args to JS object
    final jsArgs = args.jsify();

    // Call Tauri invoke
    final result = await _invoke(command.toJS, jsArgs).toDart;

    // Convert result back to Dart
    return result?.dartify();
  } catch (e) {
    throw StateError('Tauri invoke failed: $e');
  }
}

// Check if __TAURI__ global exists
bool _checkTauriExists() {
  return _tauriExists().toDart;
}

// JavaScript interop bindings
@JS('(function() { return typeof window !== "undefined" && typeof window.__TAURI__ !== "undefined"; })()')
external JSBoolean _tauriExists();

@JS('window.__TAURI__.core.invoke')
external JSPromise<JSAny?> _invoke(JSString command, JSAny? args);
