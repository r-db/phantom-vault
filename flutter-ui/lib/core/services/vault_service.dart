import 'package:flutter/foundation.dart';
import '../models/secret_entry.dart';
import '../bridge/tauri_bridge.dart';

/// Service for managing vault operations
///
/// This service communicates with the Rust backend via:
/// - Tauri IPC (desktop via web)
/// - flutter_rust_bridge FFI (mobile - not yet implemented)
///
/// Falls back to mock data when not running in Tauri.
class VaultService extends ChangeNotifier {
  final TauriBridge _bridge = TauriBridge.instance;

  bool _vaultExists = false;
  bool _isUnlocked = false;
  bool _isLoading = false;
  String? _error;
  List<SecretEntry> _secrets = [];

  // Getters
  bool get vaultExists => _vaultExists;
  bool get isUnlocked => _isUnlocked;
  bool get isLoading => _isLoading;
  String? get error => _error;
  List<SecretEntry> get secrets => _secrets;
  bool get isTauri => _bridge.isTauri;

  // Computed getters
  int get secretCount => _secrets.length;
  int get expiredCount => _secrets.where((s) => s.isExpired).length;
  int get rotationDueCount => _secrets.where((s) => s.needsRotation).length;
  List<SecretEntry> get expiredSecrets =>
      _secrets.where((s) => s.isExpired).toList();
  List<SecretEntry> get rotationDueSecrets =>
      _secrets.where((s) => s.needsRotation).toList();

  /// Initialize - check if vault exists
  Future<void> initialize() async {
    _isLoading = true;
    notifyListeners();

    try {
      if (_bridge.isTauri) {
        _vaultExists = await _bridge.invoke('check_vault_exists') as bool;
      } else {
        // Mock mode for development
        _vaultExists = false;
      }
      _error = null;
    } catch (e) {
      _error = e.toString();
      debugPrint('VaultService.initialize error: $e');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Create a new vault
  Future<bool> createVault(String password) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      if (_bridge.isTauri) {
        final result = await _bridge.invokeCommand<void>(
          'create_vault',
          {'password': password},
        );
        if (!result.success) {
          _error = result.error;
          return false;
        }
      }

      _vaultExists = true;
      _isUnlocked = true;
      _secrets = [];
      return true;
    } catch (e) {
      _error = e.toString();
      debugPrint('VaultService.createVault error: $e');
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Unlock the vault
  Future<bool> unlock(String password) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      if (_bridge.isTauri) {
        final result = await _bridge.invokeCommand<Map<String, dynamic>>(
          'unlock_vault',
          {'password': password},
          (data) => data as Map<String, dynamic>,
        );

        if (!result.success) {
          _error = result.error ?? 'Invalid password';
          return false;
        }

        _isUnlocked = true;

        // Load secrets
        await _loadSecrets();
      } else {
        // Mock mode for development
        _isUnlocked = true;
        _secrets = _generateMockSecrets();
      }

      return true;
    } catch (e) {
      _error = 'Invalid password';
      debugPrint('VaultService.unlock error: $e');
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Load secrets from backend
  Future<void> _loadSecrets() async {
    if (!_bridge.isTauri) return;

    final result = await _bridge.invokeCommand<List<dynamic>>(
      'list_secrets',
      null,
      (data) => data as List<dynamic>,
    );

    if (result.success && result.data != null) {
      _secrets = result.data!
          .map((json) => SecretEntry.fromJson(json as Map<String, dynamic>))
          .toList();
    }
  }

  /// Lock the vault
  Future<void> lock() async {
    if (_bridge.isTauri) {
      try {
        await _bridge.invoke('lock_vault');
      } catch (e) {
        debugPrint('VaultService.lock error: $e');
      }
    }

    _isUnlocked = false;
    _secrets = [];
    notifyListeners();
  }

  /// Add a new secret
  Future<bool> addSecret({
    required String reference,
    required String value,
    required SecretType type,
    String? description,
    List<String> tags = const [],
    DateTime? expiresAt,
    int? rotationReminderDays,
  }) async {
    _isLoading = true;
    notifyListeners();

    try {
      if (_bridge.isTauri) {
        final result = await _bridge.invokeCommand<Map<String, dynamic>>(
          'add_secret',
          {
            'input': {
              'reference': reference,
              'secret_type': _secretTypeToJson(type),
              'value': value,
              'description': description,
              'tags': tags,
              'expires_at': expiresAt?.toIso8601String(),
              'rotation_reminder_days': rotationReminderDays,
              'allowed_tools': <String>[],
            },
          },
          (data) => data as Map<String, dynamic>,
        );

        if (!result.success) {
          _error = result.error;
          return false;
        }

        // Reload secrets to get updated list
        await _loadSecrets();
      } else {
        // Mock mode
        final newSecret = SecretEntry(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          reference: reference,
          secretType: type,
          description: description,
          tags: tags,
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
          expiresAt: expiresAt,
          rotationReminderDays: rotationReminderDays,
        );
        _secrets.add(newSecret);
      }

      return true;
    } catch (e) {
      _error = e.toString();
      debugPrint('VaultService.addSecret error: $e');
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Update a secret's value (rotate)
  Future<bool> rotateSecret(String reference, String newValue) async {
    _isLoading = true;
    notifyListeners();

    try {
      if (_bridge.isTauri) {
        final result = await _bridge.invokeCommand<void>(
          'rotate_secret',
          {
            'reference': reference,
            'new_value': newValue,
          },
        );

        if (!result.success) {
          _error = result.error;
          return false;
        }

        await _loadSecrets();
      } else {
        // Mock mode - just update timestamp
        final index = _secrets.indexWhere((s) => s.reference == reference);
        if (index != -1) {
          final secret = _secrets[index];
          _secrets[index] = SecretEntry(
            id: secret.id,
            reference: secret.reference,
            secretType: secret.secretType,
            description: secret.description,
            tags: secret.tags,
            createdAt: secret.createdAt,
            updatedAt: DateTime.now(),
            expiresAt: secret.expiresAt,
            rotationReminderDays: secret.rotationReminderDays,
            lastRotatedAt: DateTime.now(),
          );
        }
      }

      return true;
    } catch (e) {
      _error = e.toString();
      debugPrint('VaultService.rotateSecret error: $e');
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Delete a secret
  Future<bool> deleteSecret(String reference) async {
    _isLoading = true;
    notifyListeners();

    try {
      if (_bridge.isTauri) {
        final result = await _bridge.invokeCommand<void>(
          'delete_secret',
          {'reference': reference},
        );

        if (!result.success) {
          _error = result.error;
          return false;
        }

        await _loadSecrets();
      } else {
        // Mock mode
        _secrets.removeWhere((s) => s.reference == reference);
      }

      return true;
    } catch (e) {
      _error = e.toString();
      debugPrint('VaultService.deleteSecret error: $e');
      return false;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Get secret by reference
  SecretEntry? getSecret(String reference) {
    try {
      return _secrets.firstWhere((s) => s.reference == reference);
    } catch (_) {
      return null;
    }
  }

  /// Filter secrets by tag
  List<SecretEntry> filterByTag(String tag) {
    return _secrets.where((s) => s.tags.contains(tag)).toList();
  }

  /// Filter secrets by type
  List<SecretEntry> filterByType(SecretType type) {
    return _secrets.where((s) => s.secretType == type).toList();
  }

  /// Search secrets by reference or description
  List<SecretEntry> search(String query) {
    final lowerQuery = query.toLowerCase();
    return _secrets.where((s) {
      return s.reference.toLowerCase().contains(lowerQuery) ||
          (s.description?.toLowerCase().contains(lowerQuery) ?? false);
    }).toList();
  }

  /// Get all unique tags
  List<String> getAllTags() {
    final tags = <String>{};
    for (final secret in _secrets) {
      tags.addAll(secret.tags);
    }
    return tags.toList()..sort();
  }

  /// Convert SecretType to JSON for Rust
  Map<String, dynamic> _secretTypeToJson(SecretType type) {
    switch (type) {
      case SecretType.apiKey:
        return {
          'type': 'ApiKey',
          'data': {'provider': 'generic', 'scopes': <String>[]},
        };
      case SecretType.token:
        return {
          'type': 'Token',
          'data': {'token_type': 'Bearer'},
        };
      case SecretType.connectionString:
        return {
          'type': 'ConnectionString',
          'data': {
            'db_type': 'Postgres',
            'host': '',
            'port': 5432,
            'database': '',
            'username': '',
          },
        };
      case SecretType.sshKey:
        return {
          'type': 'SshKey',
          'data': {
            'key_type': 'Ed25519',
            'public_key': '',
            'passphrase_protected': false,
          },
        };
      case SecretType.certificate:
        return {
          'type': 'Certificate',
          'data': {
            'cert_type': 'Tls',
            'public_cert': '',
            'chain': <String>[],
          },
        };
      case SecretType.generic:
        return {
          'type': 'Generic',
          'data': {'format': 'text'},
        };
    }
  }

  /// Generate mock secrets for UI testing (when not in Tauri)
  List<SecretEntry> _generateMockSecrets() {
    return [
      SecretEntry(
        id: '1',
        reference: 'openai-prod',
        secretType: SecretType.apiKey,
        description: 'OpenAI API key for production',
        tags: ['ai', 'production'],
        createdAt: DateTime.now().subtract(const Duration(days: 30)),
        updatedAt: DateTime.now().subtract(const Duration(days: 5)),
        expiresAt: DateTime.now().add(const Duration(days: 60)),
        rotationReminderDays: 90,
      ),
      SecretEntry(
        id: '2',
        reference: 'prod-db',
        secretType: SecretType.connectionString,
        description: 'Production PostgreSQL database',
        tags: ['database', 'production'],
        createdAt: DateTime.now().subtract(const Duration(days: 60)),
        updatedAt: DateTime.now().subtract(const Duration(days: 60)),
        rotationReminderDays: 30,
        lastRotatedAt: DateTime.now().subtract(const Duration(days: 45)),
      ),
      SecretEntry(
        id: '3',
        reference: 'github-deploy',
        secretType: SecretType.token,
        description: 'GitHub deploy key',
        tags: ['git', 'ci-cd'],
        createdAt: DateTime.now().subtract(const Duration(days: 90)),
        updatedAt: DateTime.now().subtract(const Duration(days: 90)),
        expiresAt: DateTime.now().subtract(const Duration(days: 5)), // Expired!
      ),
      SecretEntry(
        id: '4',
        reference: 'stripe-test',
        secretType: SecretType.apiKey,
        description: 'Stripe test API key',
        tags: ['payment', 'test'],
        createdAt: DateTime.now().subtract(const Duration(days: 15)),
        updatedAt: DateTime.now().subtract(const Duration(days: 15)),
      ),
      SecretEntry(
        id: '5',
        reference: 'aws-deploy',
        secretType: SecretType.sshKey,
        description: 'AWS EC2 SSH key',
        tags: ['aws', 'infrastructure'],
        createdAt: DateTime.now().subtract(const Duration(days: 120)),
        updatedAt: DateTime.now().subtract(const Duration(days: 120)),
      ),
    ];
  }
}
