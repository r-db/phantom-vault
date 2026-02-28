import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../core/models/secret_entry.dart';
import '../../core/services/vault_service.dart';

/// Screen for adding a new secret
class AddSecretScreen extends StatefulWidget {
  const AddSecretScreen({super.key});

  @override
  State<AddSecretScreen> createState() => _AddSecretScreenState();
}

class _AddSecretScreenState extends State<AddSecretScreen> {
  final _formKey = GlobalKey<FormState>();
  final _referenceController = TextEditingController();
  final _valueController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _tagController = TextEditingController();

  SecretType _selectedType = SecretType.apiKey;
  List<String> _tags = [];
  DateTime? _expiresAt;
  int? _rotationReminderDays;

  @override
  void dispose() {
    _referenceController.dispose();
    _valueController.dispose();
    _descriptionController.dispose();
    _tagController.dispose();
    super.dispose();
  }

  /// Auto-detect secret type from value pattern
  void _autoDetectType(String value) {
    SecretType? detected;

    if (value.startsWith('sk-') && value.length > 40) {
      detected = SecretType.apiKey; // OpenAI
    } else if (value.startsWith('ghp_') || value.startsWith('github_pat_')) {
      detected = SecretType.token; // GitHub
    } else if (value.startsWith('sk_live_') || value.startsWith('sk_test_')) {
      detected = SecretType.apiKey; // Stripe
    } else if (value.contains('://') && value.contains('@')) {
      detected = SecretType.connectionString; // Database URL
    } else if (value.startsWith('-----BEGIN') && value.contains('PRIVATE KEY')) {
      detected = SecretType.sshKey; // SSH/Private key
    } else if (value.startsWith('-----BEGIN CERTIFICATE')) {
      detected = SecretType.certificate;
    } else if (value.startsWith('AKIA')) {
      detected = SecretType.apiKey; // AWS
    }

    if (detected != null && detected != _selectedType) {
      setState(() => _selectedType = detected!);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Auto-detected: ${detected.displayName}'),
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null) {
      _valueController.text = data!.text!;
      _autoDetectType(data.text!);

      // Clear clipboard for security
      await Clipboard.setData(const ClipboardData(text: ''));

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Pasted! Clipboard cleared for security.'),
            duration: Duration(seconds: 2),
          ),
        );
      }
    }
  }

  void _addTag() {
    final tag = _tagController.text.trim();
    if (tag.isNotEmpty && !_tags.contains(tag)) {
      setState(() {
        _tags.add(tag);
        _tagController.clear();
      });
    }
  }

  void _removeTag(String tag) {
    setState(() => _tags.remove(tag));
  }

  Future<void> _selectExpirationDate() async {
    final date = await showDatePicker(
      context: context,
      initialDate: _expiresAt ?? DateTime.now().add(const Duration(days: 90)),
      firstDate: DateTime.now(),
      lastDate: DateTime.now().add(const Duration(days: 365 * 5)),
    );

    if (date != null) {
      setState(() => _expiresAt = date);
    }
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;

    final vaultService = context.read<VaultService>();

    final success = await vaultService.addSecret(
      reference: _referenceController.text.trim(),
      value: _valueController.text,
      type: _selectedType,
      description: _descriptionController.text.trim().isEmpty
          ? null
          : _descriptionController.text.trim(),
      tags: _tags,
      expiresAt: _expiresAt,
      rotationReminderDays: _rotationReminderDays,
    );

    if (success && mounted) {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Secret added successfully')),
      );
    } else if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(vaultService.error ?? 'Failed to add secret'),
          backgroundColor: Colors.red.shade700,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Add Secret'),
        actions: [
          TextButton.icon(
            onPressed: _save,
            icon: const Icon(Icons.check),
            label: const Text('Save'),
          ),
        ],
      ),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Reference name
            TextFormField(
              controller: _referenceController,
              decoration: const InputDecoration(
                labelText: 'Reference Name *',
                hintText: 'e.g., openai-prod, my-db',
                helperText: 'A memorable name to reference this secret',
              ),
              validator: (value) {
                if (value == null || value.trim().isEmpty) {
                  return 'Reference name is required';
                }
                if (value.contains(' ')) {
                  return 'Reference name cannot contain spaces';
                }
                return null;
              },
            ),
            const SizedBox(height: 24),

            // Secret value with paste button
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: TextFormField(
                    controller: _valueController,
                    decoration: const InputDecoration(
                      labelText: 'Secret Value *',
                      hintText: 'Paste your API key, token, or secret',
                    ),
                    maxLines: 3,
                    obscureText: false, // Show value while entering
                    onChanged: _autoDetectType,
                    validator: (value) {
                      if (value == null || value.isEmpty) {
                        return 'Secret value is required';
                      }
                      return null;
                    },
                  ),
                ),
                const SizedBox(width: 12),
                FilledButton.tonalIcon(
                  onPressed: _pasteFromClipboard,
                  icon: const Icon(Icons.paste),
                  label: const Text('Paste'),
                  style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 20,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),

            // Secret type
            DropdownButtonFormField<SecretType>(
              value: _selectedType,
              decoration: const InputDecoration(
                labelText: 'Secret Type',
              ),
              items: SecretType.values.map((type) {
                return DropdownMenuItem(
                  value: type,
                  child: Text(type.displayName),
                );
              }).toList(),
              onChanged: (value) {
                if (value != null) {
                  setState(() => _selectedType = value);
                }
              },
            ),
            const SizedBox(height: 24),

            // Description
            TextFormField(
              controller: _descriptionController,
              decoration: const InputDecoration(
                labelText: 'Description (optional)',
                hintText: 'What is this secret for?',
              ),
              maxLines: 2,
            ),
            const SizedBox(height: 24),

            // Tags
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _tagController,
                    decoration: const InputDecoration(
                      labelText: 'Tags',
                      hintText: 'Add tags for organization',
                    ),
                    onSubmitted: (_) => _addTag(),
                  ),
                ),
                const SizedBox(width: 12),
                IconButton.filled(
                  onPressed: _addTag,
                  icon: const Icon(Icons.add),
                ),
              ],
            ),
            if (_tags.isNotEmpty) ...[
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _tags.map((tag) {
                  return Chip(
                    label: Text(tag),
                    onDeleted: () => _removeTag(tag),
                  );
                }).toList(),
              ),
            ],
            const SizedBox(height: 24),

            // Expiration and rotation section
            Text(
              'Expiration & Rotation',
              style: theme.textTheme.titleSmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 12),

            // Expiration date
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.event),
              title: const Text('Expiration Date'),
              subtitle: Text(
                _expiresAt != null
                    ? '${_expiresAt!.day}/${_expiresAt!.month}/${_expiresAt!.year}'
                    : 'No expiration set',
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_expiresAt != null)
                    IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () => setState(() => _expiresAt = null),
                    ),
                  IconButton(
                    icon: const Icon(Icons.calendar_month),
                    onPressed: _selectExpirationDate,
                  ),
                ],
              ),
            ),

            // Rotation reminder
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.autorenew),
              title: const Text('Rotation Reminder'),
              subtitle: Text(
                _rotationReminderDays != null
                    ? 'Every $_rotationReminderDays days'
                    : 'No reminder set',
              ),
              trailing: DropdownButton<int?>(
                value: _rotationReminderDays,
                underline: const SizedBox(),
                items: [
                  const DropdownMenuItem(value: null, child: Text('None')),
                  const DropdownMenuItem(value: 30, child: Text('30 days')),
                  const DropdownMenuItem(value: 60, child: Text('60 days')),
                  const DropdownMenuItem(value: 90, child: Text('90 days')),
                  const DropdownMenuItem(value: 180, child: Text('180 days')),
                ],
                onChanged: (value) {
                  setState(() => _rotationReminderDays = value);
                },
              ),
            ),

            const SizedBox(height: 32),

            // Security note
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: colorScheme.surfaceContainerHighest.withOpacity(0.5),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.security,
                    color: colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'Your secret will be encrypted with AES-256-GCM before storage. '
                      'The value is never stored in plaintext.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
