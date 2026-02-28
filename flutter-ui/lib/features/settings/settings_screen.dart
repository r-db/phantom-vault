import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/services/theme_service.dart';
import '../../core/services/vault_service.dart';

/// Settings screen
class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final themeService = context.watch<ThemeService>();
    final vaultService = context.watch<VaultService>();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          // Appearance section
          _buildSectionHeader(context, 'Appearance'),
          ListTile(
            leading: const Icon(Icons.palette_outlined),
            title: const Text('Theme'),
            subtitle: Text(_getThemeModeName(themeService.themeMode)),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showThemeDialog(context, themeService),
          ),
          const Divider(),

          // Security section
          _buildSectionHeader(context, 'Security'),
          SwitchListTile(
            secondary: const Icon(Icons.timer_outlined),
            title: const Text('Auto-lock'),
            subtitle: const Text('Lock vault after 5 minutes of inactivity'),
            value: true, // TODO: Get from config
            onChanged: (value) {
              // TODO: Update config
            },
          ),
          ListTile(
            leading: const Icon(Icons.lock_clock_outlined),
            title: const Text('Auto-lock Timeout'),
            subtitle: const Text('5 minutes'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showTimeoutDialog(context),
          ),
          ListTile(
            leading: const Icon(Icons.password_outlined),
            title: const Text('Change Master Password'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showChangePasswordDialog(context),
          ),
          const Divider(),

          // MCP Server section
          _buildSectionHeader(context, 'MCP Server'),
          SwitchListTile(
            secondary: const Icon(Icons.dns_outlined),
            title: const Text('MCP Server'),
            subtitle: const Text('Allow Claude Code to access credentials'),
            value: true, // TODO: Get from config
            onChanged: (value) {
              // TODO: Update config
            },
          ),
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Server Status'),
            subtitle: const Text('Running on stdio'),
            trailing: Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                color: Colors.green,
                shape: BoxShape.circle,
              ),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.code),
            title: const Text('Configure Claude Code'),
            subtitle: const Text('View setup instructions'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showMcpInstructions(context),
          ),
          const Divider(),

          // Data section
          _buildSectionHeader(context, 'Data'),
          ListTile(
            leading: const Icon(Icons.backup_outlined),
            title: const Text('Backup Vault'),
            subtitle: const Text('Export encrypted backup'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              // TODO: Implement backup
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Backup feature coming soon')),
              );
            },
          ),
          ListTile(
            leading: const Icon(Icons.restore),
            title: const Text('Restore from Backup'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              // TODO: Implement restore
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Restore feature coming soon')),
              );
            },
          ),
          ListTile(
            leading: const Icon(Icons.history),
            title: const Text('Audit Log'),
            subtitle: Text('${vaultService.secretCount} entries'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              // TODO: Show audit log
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Audit log coming soon')),
              );
            },
          ),
          const Divider(),

          // About section
          _buildSectionHeader(context, 'About'),
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Version'),
            subtitle: const Text('0.1.0'),
          ),
          ListTile(
            leading: const Icon(Icons.description_outlined),
            title: const Text('Licenses'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              showLicensePage(
                context: context,
                applicationName: 'Vault Secrets',
                applicationVersion: '0.1.0',
              );
            },
          ),
          const SizedBox(height: 24),

          // Danger zone
          _buildSectionHeader(context, 'Danger Zone', isDestructive: true),
          ListTile(
            leading: Icon(Icons.delete_forever, color: colorScheme.error),
            title: Text('Delete Vault', style: TextStyle(color: colorScheme.error)),
            subtitle: const Text('Permanently delete all secrets'),
            onTap: () => _showDeleteVaultDialog(context),
          ),
          const SizedBox(height: 48),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(
    BuildContext context,
    String title, {
    bool isDestructive = false,
  }) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
      child: Text(
        title,
        style: TextStyle(
          color: isDestructive ? colorScheme.error : colorScheme.primary,
          fontWeight: FontWeight.w600,
          fontSize: 13,
        ),
      ),
    );
  }

  String _getThemeModeName(ThemeMode mode) {
    switch (mode) {
      case ThemeMode.system:
        return 'System';
      case ThemeMode.light:
        return 'Light';
      case ThemeMode.dark:
        return 'Dark';
    }
  }

  void _showThemeDialog(BuildContext context, ThemeService themeService) {
    showDialog(
      context: context,
      builder: (context) {
        return SimpleDialog(
          title: const Text('Theme'),
          children: ThemeMode.values.map((mode) {
            return RadioListTile<ThemeMode>(
              title: Text(_getThemeModeName(mode)),
              value: mode,
              groupValue: themeService.themeMode,
              onChanged: (value) {
                if (value != null) {
                  themeService.setThemeMode(value);
                }
                Navigator.pop(context);
              },
            );
          }).toList(),
        );
      },
    );
  }

  void _showTimeoutDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return SimpleDialog(
          title: const Text('Auto-lock Timeout'),
          children: [
            _buildTimeoutOption(context, '1 minute', 60),
            _buildTimeoutOption(context, '5 minutes', 300),
            _buildTimeoutOption(context, '15 minutes', 900),
            _buildTimeoutOption(context, '30 minutes', 1800),
            _buildTimeoutOption(context, 'Never', 0),
          ],
        );
      },
    );
  }

  Widget _buildTimeoutOption(BuildContext context, String label, int seconds) {
    return RadioListTile<int>(
      title: Text(label),
      value: seconds,
      groupValue: 300, // TODO: Get from config
      onChanged: (value) {
        // TODO: Update config
        Navigator.pop(context);
      },
    );
  }

  void _showChangePasswordDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Change Master Password'),
          content: const Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                obscureText: true,
                decoration: InputDecoration(
                  labelText: 'Current Password',
                ),
              ),
              SizedBox(height: 16),
              TextField(
                obscureText: true,
                decoration: InputDecoration(
                  labelText: 'New Password',
                ),
              ),
              SizedBox(height: 16),
              TextField(
                obscureText: true,
                decoration: InputDecoration(
                  labelText: 'Confirm New Password',
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                // TODO: Implement password change
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Password change coming soon')),
                );
              },
              child: const Text('Change'),
            ),
          ],
        );
      },
    );
  }

  void _showMcpInstructions(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Configure Claude Code'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  'Add the following to your Claude Code configuration:',
                  style: TextStyle(fontWeight: FontWeight.w500),
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const SelectableText(
                    '~/.claude/claude_config.json\n\n'
                    '{\n'
                    '  "mcpServers": {\n'
                    '    "vault-secrets": {\n'
                    '      "command": "/path/to/vault-mcp-server",\n'
                    '      "args": []\n'
                    '    }\n'
                    '  }\n'
                    '}',
                    style: TextStyle(
                      fontFamily: 'JetBrainsMono',
                      fontSize: 12,
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                const Text(
                  'After configuring, restart Claude Code to enable '
                  'secure credential injection.',
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Close'),
            ),
          ],
        );
      },
    );
  }

  void _showDeleteVaultDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Delete Vault'),
          content: const Text(
            'This will permanently delete all your secrets. '
            'This action cannot be undone.\n\n'
            'Are you absolutely sure?',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                // TODO: Implement vault deletion
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Vault deletion coming soon')),
                );
              },
              style: FilledButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.error,
              ),
              child: const Text('Delete Everything'),
            ),
          ],
        );
      },
    );
  }
}
