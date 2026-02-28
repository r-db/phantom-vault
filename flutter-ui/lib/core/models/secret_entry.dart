/// Types of secrets
enum SecretType {
  apiKey,
  token,
  connectionString,
  sshKey,
  certificate,
  generic,
}

extension SecretTypeExtension on SecretType {
  String get displayName {
    switch (this) {
      case SecretType.apiKey:
        return 'API Key';
      case SecretType.token:
        return 'Token';
      case SecretType.connectionString:
        return 'Connection String';
      case SecretType.sshKey:
        return 'SSH Key';
      case SecretType.certificate:
        return 'Certificate';
      case SecretType.generic:
        return 'Generic';
    }
  }

  String get icon {
    switch (this) {
      case SecretType.apiKey:
        return 'key';
      case SecretType.token:
        return 'token';
      case SecretType.connectionString:
        return 'database';
      case SecretType.sshKey:
        return 'terminal';
      case SecretType.certificate:
        return 'verified_user';
      case SecretType.generic:
        return 'lock';
    }
  }
}

/// Secret entry model (mirrors Rust SecretEntry)
class SecretEntry {
  final String id;
  final String reference;
  final SecretType secretType;
  final String? description;
  final List<String> tags;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? expiresAt;
  final int? rotationReminderDays;
  final DateTime? lastRotatedAt;
  final int? usageLimit;
  final int usageCount;
  final DateTime? lastUsedAt;
  final List<String> allowedTools;
  final bool autoInject;

  SecretEntry({
    required this.id,
    required this.reference,
    required this.secretType,
    this.description,
    this.tags = const [],
    required this.createdAt,
    required this.updatedAt,
    this.expiresAt,
    this.rotationReminderDays,
    this.lastRotatedAt,
    this.usageLimit,
    this.usageCount = 0,
    this.lastUsedAt,
    this.allowedTools = const [],
    this.autoInject = true,
  });

  /// Check if the secret is expired
  bool get isExpired {
    if (expiresAt == null) return false;
    return DateTime.now().isAfter(expiresAt!);
  }

  /// Check if rotation is due
  bool get needsRotation {
    if (rotationReminderDays == null) return false;
    final lastRotation = lastRotatedAt ?? createdAt;
    final elapsed = DateTime.now().difference(lastRotation).inDays;
    return elapsed >= rotationReminderDays!;
  }

  /// Check if usage limit is exceeded
  bool get isUsageExceeded {
    if (usageLimit == null) return false;
    return usageCount >= usageLimit!;
  }

  /// Days until expiration (null if no expiration set)
  int? get daysUntilExpiration {
    if (expiresAt == null) return null;
    return expiresAt!.difference(DateTime.now()).inDays;
  }

  /// Status badge text
  String? get statusBadge {
    if (isExpired) return 'EXPIRED';
    if (needsRotation) return 'ROTATE';
    if (isUsageExceeded) return 'LIMIT';

    final days = daysUntilExpiration;
    if (days != null && days <= 7) {
      return 'EXPIRES SOON';
    }

    return null;
  }

  /// Status badge color
  StatusSeverity get statusSeverity {
    if (isExpired || isUsageExceeded) return StatusSeverity.critical;
    if (needsRotation) return StatusSeverity.warning;

    final days = daysUntilExpiration;
    if (days != null && days <= 7) return StatusSeverity.critical;
    if (days != null && days <= 14) return StatusSeverity.warning;

    return StatusSeverity.ok;
  }

  /// Create from JSON (from Rust backend)
  factory SecretEntry.fromJson(Map<String, dynamic> json) {
    return SecretEntry(
      id: json['id'] as String,
      reference: json['reference'] as String,
      secretType: _parseSecretType(json['secret_type'] as String),
      description: json['description'] as String?,
      tags: (json['tags'] as List<dynamic>?)?.cast<String>() ?? [],
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      expiresAt: json['expires_at'] != null
          ? DateTime.parse(json['expires_at'] as String)
          : null,
      rotationReminderDays: json['rotation_reminder_days'] as int?,
      lastRotatedAt: json['last_rotated_at'] != null
          ? DateTime.parse(json['last_rotated_at'] as String)
          : null,
      usageLimit: json['usage_limit'] as int?,
      usageCount: json['usage_count'] as int? ?? 0,
      lastUsedAt: json['last_used_at'] != null
          ? DateTime.parse(json['last_used_at'] as String)
          : null,
      allowedTools: (json['allowed_tools'] as List<dynamic>?)?.cast<String>() ?? [],
      autoInject: json['auto_inject'] as bool? ?? true,
    );
  }

  /// Convert to JSON
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'reference': reference,
      'secret_type': secretType.name,
      'description': description,
      'tags': tags,
      'created_at': createdAt.toIso8601String(),
      'updated_at': updatedAt.toIso8601String(),
      'expires_at': expiresAt?.toIso8601String(),
      'rotation_reminder_days': rotationReminderDays,
      'last_rotated_at': lastRotatedAt?.toIso8601String(),
      'usage_limit': usageLimit,
      'usage_count': usageCount,
      'last_used_at': lastUsedAt?.toIso8601String(),
      'allowed_tools': allowedTools,
      'auto_inject': autoInject,
    };
  }

  static SecretType _parseSecretType(String type) {
    switch (type.toLowerCase()) {
      case 'apikey':
      case 'api_key':
        return SecretType.apiKey;
      case 'token':
        return SecretType.token;
      case 'connectionstring':
      case 'connection_string':
        return SecretType.connectionString;
      case 'sshkey':
      case 'ssh_key':
        return SecretType.sshKey;
      case 'certificate':
        return SecretType.certificate;
      default:
        return SecretType.generic;
    }
  }
}

/// Status severity levels
enum StatusSeverity {
  ok,
  warning,
  critical,
}
