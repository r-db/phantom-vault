import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';

import '../../core/models/secret_entry.dart';
import '../../core/services/vault_service.dart';

/// Screen for viewing and editing a secret
class SecretDetailScreen extends StatefulWidget {
  final String reference;

  const SecretDetailScreen({
    super.key,
    required this.reference,
  });

  @override
  State<SecretDetailScreen> createState() => _SecretDetailScreenState();
}

class _SecretDetailScreenState extends State<SecretDetailScreen> {
  bool _showValue = false;

  SecretEntry? _getSecret(VaultService vaultService) {
    return vaultService.getSecret(widget.reference);
  }

  Future<void> _copyReference() async {
    await Clipboard.setData(ClipboardData(text: widget.reference));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Reference copied to clipboard')),
      );
    }
  }

  Future<void> _rotateSecret() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Rotate Secret'),
          content: const Text(
            'This will mark the secret for rotation. You will need to '
            'update the value with a new credential.\n\n'
            'Are you sure you want to continue?',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Rotate'),
            ),
          ],
        );
      },
    );

    if (confirmed == true && mounted) {
      // TODO: Implement rotation
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Secret marked for rotation')),
      );
    }
  }

  Future<void> _deleteSecret() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Delete Secret'),
          content: Text(
            'Are you sure you want to delete "${widget.reference}"?\n\n'
            'This action cannot be undone.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              style: FilledButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.error,
              ),
              child: const Text('Delete'),
            ),
          ],
        );
      },
    );

    if (confirmed == true && mounted) {
      final vaultService = context.read<VaultService>();
      final success = await vaultService.deleteSecret(widget.reference);

      if (success && mounted) {
        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Secret deleted')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final vaultService = context.watch<VaultService>();
    final secret = _getSecret(vaultService);
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    if (secret == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Secret Not Found')),
        body: const Center(child: Text('Secret not found')),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(secret.reference),
        actions: [
          IconButton(
            icon: const Icon(Icons.content_copy),
            onPressed: _copyReference,
            tooltip: 'Copy Reference',
          ),
          PopupMenuButton<String>(
            onSelected: (value) {
              switch (value) {
                case 'rotate':
                  _rotateSecret();
                  break;
                case 'delete':
                  _deleteSecret();
                  break;
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'rotate',
                child: ListTile(
                  leading: Icon(Icons.autorenew),
                  title: Text('Rotate Secret'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              PopupMenuItem(
                value: 'delete',
                child: ListTile(
                  leading: Icon(Icons.delete, color: colorScheme.error),
                  title: Text('Delete', style: TextStyle(color: colorScheme.error)),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ],
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Status banner
          if (secret.statusBadge != null)
            _buildStatusBanner(secret, colorScheme),

          // Type and icon
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Container(
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: colorScheme.primaryContainer,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Icon(
                      _getTypeIcon(secret.secretType),
                      color: colorScheme.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          secret.secretType.displayName,
                          style: theme.textTheme.titleMedium,
                        ),
                        if (secret.description != null)
                          Text(
                            secret.description!,
                            style: theme.textTheme.bodyMedium?.copyWith(
                              color: colorScheme.onSurfaceVariant,
                            ),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Tags
          if (secret.tags.isNotEmpty) ...[
            Text(
              'Tags',
              style: theme.textTheme.titleSmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: secret.tags.map((tag) {
                return Chip(label: Text(tag));
              }).toList(),
            ),
            const SizedBox(height: 24),
          ],

          // Metadata section
          Text(
            'Details',
            style: theme.textTheme.titleSmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Card(
            child: Column(
              children: [
                _buildDetailRow('Created', _formatDate(secret.createdAt)),
                _buildDivider(),
                _buildDetailRow('Last Updated', _formatDate(secret.updatedAt)),
                if (secret.expiresAt != null) ...[
                  _buildDivider(),
                  _buildDetailRow(
                    'Expires',
                    _formatDate(secret.expiresAt!),
                    trailing: secret.isExpired
                        ? _buildBadge('EXPIRED', colorScheme.error)
                        : secret.daysUntilExpiration! <= 14
                            ? _buildBadge(
                                '${secret.daysUntilExpiration} days',
                                Colors.orange,
                              )
                            : null,
                  ),
                ],
                if (secret.rotationReminderDays != null) ...[
                  _buildDivider(),
                  _buildDetailRow(
                    'Rotation',
                    'Every ${secret.rotationReminderDays} days',
                    trailing: secret.needsRotation
                        ? _buildBadge('DUE', Colors.orange)
                        : null,
                  ),
                ],
                if (secret.lastRotatedAt != null) ...[
                  _buildDivider(),
                  _buildDetailRow(
                    'Last Rotated',
                    _formatDate(secret.lastRotatedAt!),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Usage stats
          Text(
            'Usage',
            style: theme.textTheme.titleSmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Card(
            child: Column(
              children: [
                _buildDetailRow(
                  'Usage Count',
                  secret.usageCount.toString(),
                  trailing: secret.usageLimit != null
                      ? Text(
                          '/ ${secret.usageLimit}',
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: colorScheme.onSurfaceVariant,
                          ),
                        )
                      : null,
                ),
                if (secret.lastUsedAt != null) ...[
                  _buildDivider(),
                  _buildDetailRow('Last Used', _formatDate(secret.lastUsedAt!)),
                ],
                _buildDivider(),
                _buildDetailRow(
                  'Auto-Inject',
                  secret.autoInject ? 'Enabled' : 'Disabled',
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Allowed tools
          if (secret.allowedTools.isNotEmpty) ...[
            Text(
              'Allowed Tools',
              style: theme.textTheme.titleSmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: secret.allowedTools.map((tool) {
                return Chip(
                  avatar: const Icon(Icons.build, size: 18),
                  label: Text(tool),
                );
              }).toList(),
            ),
            const SizedBox(height: 24),
          ],

          // Actions
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _rotateSecret,
                  icon: const Icon(Icons.autorenew),
                  label: const Text('Rotate'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FilledButton.icon(
                  onPressed: () {
                    // TODO: Use secret
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Secret usage will be handled by MCP server'),
                      ),
                    );
                  },
                  icon: const Icon(Icons.play_arrow),
                  label: const Text('Use'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildStatusBanner(SecretEntry secret, ColorScheme colorScheme) {
    Color backgroundColor;
    Color iconColor;
    String message;

    switch (secret.statusSeverity) {
      case StatusSeverity.critical:
        backgroundColor = colorScheme.errorContainer;
        iconColor = colorScheme.error;
        message = secret.isExpired
            ? 'This secret has expired'
            : secret.isUsageExceeded
                ? 'Usage limit exceeded'
                : 'Expires soon';
        break;
      case StatusSeverity.warning:
        backgroundColor = Colors.orange.shade100;
        iconColor = Colors.orange.shade700;
        message = secret.needsRotation
            ? 'Rotation is due'
            : 'Expires in ${secret.daysUntilExpiration} days';
        break;
      case StatusSeverity.ok:
        return const SizedBox.shrink();
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Icon(Icons.warning_amber, color: iconColor),
          const SizedBox(width: 12),
          Expanded(child: Text(message)),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, {Widget? trailing}) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        children: [
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Text(value),
          if (trailing != null) ...[
            const SizedBox(width: 8),
            trailing,
          ],
        ],
      ),
    );
  }

  Widget _buildDivider() {
    return Divider(
      height: 1,
      indent: 16,
      endIndent: 16,
      color: Theme.of(context).colorScheme.outlineVariant,
    );
  }

  Widget _buildBadge(String text, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        text,
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }

  IconData _getTypeIcon(SecretType type) {
    switch (type) {
      case SecretType.apiKey:
        return Icons.key;
      case SecretType.token:
        return Icons.token;
      case SecretType.connectionString:
        return Icons.storage;
      case SecretType.sshKey:
        return Icons.terminal;
      case SecretType.certificate:
        return Icons.verified_user;
      case SecretType.generic:
        return Icons.lock;
    }
  }

  String _formatDate(DateTime date) {
    return DateFormat('MMM d, yyyy HH:mm').format(date);
  }
}
