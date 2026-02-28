import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models/secret_entry.dart';
import '../../core/services/vault_service.dart';
import '../../widgets/secret_card.dart';
import '../add_secret/add_secret_screen.dart';
import '../secret_detail/secret_detail_screen.dart';
import '../settings/settings_screen.dart';

/// Main secrets list screen
class SecretsListScreen extends StatefulWidget {
  const SecretsListScreen({super.key});

  @override
  State<SecretsListScreen> createState() => _SecretsListScreenState();
}

class _SecretsListScreenState extends State<SecretsListScreen> {
  String _searchQuery = '';
  SecretType? _typeFilter;
  String? _tagFilter;

  List<SecretEntry> _getFilteredSecrets(VaultService vaultService) {
    var secrets = vaultService.secrets;

    if (_searchQuery.isNotEmpty) {
      secrets = vaultService.search(_searchQuery);
    }

    if (_typeFilter != null) {
      secrets = secrets.where((s) => s.secretType == _typeFilter).toList();
    }

    if (_tagFilter != null) {
      secrets = secrets.where((s) => s.tags.contains(_tagFilter)).toList();
    }

    return secrets;
  }

  void _openAddSecret() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const AddSecretScreen()),
    );
  }

  void _openSecretDetail(SecretEntry secret) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SecretDetailScreen(reference: secret.reference),
      ),
    );
  }

  void _openSettings() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => const SettingsScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final vaultService = context.watch<VaultService>();
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final secrets = _getFilteredSecrets(vaultService);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault Secrets'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: _openSettings,
            tooltip: 'Settings',
          ),
          IconButton(
            icon: const Icon(Icons.lock_outline),
            onPressed: () => vaultService.lock(),
            tooltip: 'Lock Vault',
          ),
        ],
      ),
      body: Column(
        children: [
          // Status bar
          if (vaultService.expiredCount > 0 || vaultService.rotationDueCount > 0)
            _buildStatusBar(vaultService, colorScheme),

          // Search and filters
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                // Search bar
                TextField(
                  decoration: InputDecoration(
                    hintText: 'Search secrets...',
                    prefixIcon: const Icon(Icons.search),
                    suffixIcon: _searchQuery.isNotEmpty
                        ? IconButton(
                            icon: const Icon(Icons.clear),
                            onPressed: () {
                              setState(() => _searchQuery = '');
                            },
                          )
                        : null,
                  ),
                  onChanged: (value) {
                    setState(() => _searchQuery = value);
                  },
                ),
                const SizedBox(height: 12),

                // Filter chips
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: [
                      // Type filter dropdown
                      _buildFilterChip(
                        label: _typeFilter?.displayName ?? 'All Types',
                        isSelected: _typeFilter != null,
                        onTap: () => _showTypeFilterDialog(),
                      ),
                      const SizedBox(width: 8),

                      // Tag filter dropdown
                      _buildFilterChip(
                        label: _tagFilter ?? 'All Tags',
                        isSelected: _tagFilter != null,
                        onTap: () => _showTagFilterDialog(vaultService),
                      ),

                      // Clear filters
                      if (_typeFilter != null || _tagFilter != null) ...[
                        const SizedBox(width: 8),
                        ActionChip(
                          label: const Text('Clear'),
                          avatar: const Icon(Icons.clear, size: 18),
                          onPressed: () {
                            setState(() {
                              _typeFilter = null;
                              _tagFilter = null;
                            });
                          },
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
          ),

          // Secrets list
          Expanded(
            child: secrets.isEmpty
                ? _buildEmptyState()
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    itemCount: secrets.length,
                    itemBuilder: (context, index) {
                      final secret = secrets[index];
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 12),
                        child: SecretCard(
                          secret: secret,
                          onTap: () => _openSecretDetail(secret),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _openAddSecret,
        icon: const Icon(Icons.add),
        label: const Text('Add Secret'),
      ),
    );
  }

  Widget _buildStatusBar(VaultService vaultService, ColorScheme colorScheme) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      color: colorScheme.errorContainer,
      child: Row(
        children: [
          Icon(Icons.warning_amber, color: colorScheme.error),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              _buildStatusMessage(vaultService),
              style: TextStyle(color: colorScheme.onErrorContainer),
            ),
          ),
          TextButton(
            onPressed: () {
              // TODO: Show expired/rotation due secrets
            },
            child: const Text('View'),
          ),
        ],
      ),
    );
  }

  String _buildStatusMessage(VaultService vaultService) {
    final parts = <String>[];
    if (vaultService.expiredCount > 0) {
      parts.add('${vaultService.expiredCount} expired');
    }
    if (vaultService.rotationDueCount > 0) {
      parts.add('${vaultService.rotationDueCount} need rotation');
    }
    return '${parts.join(', ')} secrets';
  }

  Widget _buildFilterChip({
    required String label,
    required bool isSelected,
    required VoidCallback onTap,
  }) {
    return FilterChip(
      label: Text(label),
      selected: isSelected,
      onSelected: (_) => onTap(),
      avatar: isSelected ? const Icon(Icons.check, size: 18) : null,
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.key_off,
            size: 64,
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text(
            _searchQuery.isNotEmpty || _typeFilter != null || _tagFilter != null
                ? 'No secrets match your filters'
                : 'No secrets yet',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
          const SizedBox(height: 8),
          Text(
            'Add your first secret to get started',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
        ],
      ),
    );
  }

  void _showTypeFilterDialog() {
    showDialog(
      context: context,
      builder: (context) {
        return SimpleDialog(
          title: const Text('Filter by Type'),
          children: [
            ListTile(
              title: const Text('All Types'),
              selected: _typeFilter == null,
              onTap: () {
                setState(() => _typeFilter = null);
                Navigator.pop(context);
              },
            ),
            ...SecretType.values.map((type) {
              return ListTile(
                title: Text(type.displayName),
                selected: _typeFilter == type,
                onTap: () {
                  setState(() => _typeFilter = type);
                  Navigator.pop(context);
                },
              );
            }),
          ],
        );
      },
    );
  }

  void _showTagFilterDialog(VaultService vaultService) {
    final tags = vaultService.getAllTags();

    showDialog(
      context: context,
      builder: (context) {
        return SimpleDialog(
          title: const Text('Filter by Tag'),
          children: [
            ListTile(
              title: const Text('All Tags'),
              selected: _tagFilter == null,
              onTap: () {
                setState(() => _tagFilter = null);
                Navigator.pop(context);
              },
            ),
            ...tags.map((tag) {
              return ListTile(
                title: Text(tag),
                selected: _tagFilter == tag,
                onTap: () {
                  setState(() => _tagFilter = tag);
                  Navigator.pop(context);
                },
              );
            }),
          ],
        );
      },
    );
  }
}
