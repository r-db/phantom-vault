import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';

// Conditional import for web platform
import 'tauri_bridge_stub.dart'
    if (dart.library.js_interop) 'tauri_bridge_web.dart' as platform;

/// Bridge to communicate with Tauri backend via IPC
///
/// On web (Tauri), uses JavaScript interop to call Tauri's invoke function.
/// On other platforms, throws UnsupportedError (mobile uses FFI instead).
class TauriBridge {
  static TauriBridge? _instance;

  TauriBridge._();

  /// Get singleton instance
  static TauriBridge get instance {
    _instance ??= TauriBridge._();
    return _instance!;
  }

  /// Check if running inside Tauri
  bool get isTauri => platform.isTauri();

  /// Invoke a Tauri command and return raw result
  Future<dynamic> invoke(String command, [Map<String, dynamic>? args]) {
    return platform.invoke(command, args ?? {});
  }

  /// Invoke a command expecting a CommandResult response
  Future<CommandResult<T>> invokeCommand<T>(
    String command, [
    Map<String, dynamic>? args,
    T Function(dynamic)? parser,
  ]) async {
    final result = await invoke(command, args);

    if (result is Map<String, dynamic>) {
      return CommandResult.fromJson(result, parser);
    }

    // Try parsing as JSON string
    if (result is String) {
      final json = jsonDecode(result) as Map<String, dynamic>;
      return CommandResult.fromJson(json, parser);
    }

    throw TauriBridgeException('Unexpected result type: ${result.runtimeType}');
  }
}

/// Generic command result from Tauri
class CommandResult<T> {
  final bool success;
  final T? data;
  final String? error;

  CommandResult({
    required this.success,
    this.data,
    this.error,
  });

  factory CommandResult.fromJson(
    Map<String, dynamic> json, [
    T Function(dynamic)? parser,
  ]) {
    final success = json['success'] as bool? ?? false;
    final error = json['error'] as String?;

    T? data;
    if (success && json['data'] != null && parser != null) {
      data = parser(json['data']);
    } else if (success && json['data'] != null) {
      data = json['data'] as T?;
    }

    return CommandResult(
      success: success,
      data: data,
      error: error,
    );
  }

  /// Throw if not successful
  T get dataOrThrow {
    if (!success) {
      throw TauriBridgeException(error ?? 'Unknown error');
    }
    if (data == null) {
      throw TauriBridgeException('No data returned');
    }
    return data!;
  }
}

/// Exception for Tauri bridge errors
class TauriBridgeException implements Exception {
  final String message;
  TauriBridgeException(this.message);

  @override
  String toString() => 'TauriBridgeException: $message';
}
