import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/services/vault_service.dart';

/// Unlock screen - Master password entry
class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  bool _obscurePassword = true;
  bool _isCreatingVault = false;

  @override
  void dispose() {
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _unlock() async {
    if (_passwordController.text.isEmpty) {
      _showError('Please enter your master password');
      return;
    }

    final vaultService = context.read<VaultService>();
    final success = await vaultService.unlock(_passwordController.text);

    if (!success && mounted) {
      _showError(vaultService.error ?? 'Failed to unlock vault');
    }
  }

  Future<void> _createVault() async {
    if (_passwordController.text.isEmpty) {
      _showError('Please enter a master password');
      return;
    }

    if (_passwordController.text.length < 8) {
      _showError('Password must be at least 8 characters');
      return;
    }

    if (_passwordController.text != _confirmPasswordController.text) {
      _showError('Passwords do not match');
      return;
    }

    final vaultService = context.read<VaultService>();
    final success = await vaultService.createVault(_passwordController.text);

    if (!success && mounted) {
      _showError(vaultService.error ?? 'Failed to create vault');
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.red.shade700,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final vaultService = context.watch<VaultService>();
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 400),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Logo/Icon
                  Icon(
                    Icons.security,
                    size: 80,
                    color: colorScheme.primary,
                  ),
                  const SizedBox(height: 24),

                  // Title
                  Text(
                    'Vault Secrets',
                    style: theme.textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),

                  // Subtitle
                  Text(
                    _isCreatingVault
                        ? 'Create your secure vault'
                        : 'Enter your master password',
                    style: theme.textTheme.bodyLarge?.copyWith(
                      color: colorScheme.onSurfaceVariant,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 48),

                  // Password field
                  TextField(
                    controller: _passwordController,
                    obscureText: _obscurePassword,
                    autofocus: true,
                    decoration: InputDecoration(
                      labelText: 'Master Password',
                      prefixIcon: const Icon(Icons.lock_outline),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _obscurePassword
                              ? Icons.visibility_outlined
                              : Icons.visibility_off_outlined,
                        ),
                        onPressed: () {
                          setState(() => _obscurePassword = !_obscurePassword);
                        },
                      ),
                    ),
                    onSubmitted: (_) {
                      if (!_isCreatingVault) _unlock();
                    },
                  ),
                  const SizedBox(height: 16),

                  // Confirm password field (only when creating)
                  if (_isCreatingVault) ...[
                    TextField(
                      controller: _confirmPasswordController,
                      obscureText: _obscurePassword,
                      decoration: InputDecoration(
                        labelText: 'Confirm Password',
                        prefixIcon: const Icon(Icons.lock_outline),
                      ),
                      onSubmitted: (_) => _createVault(),
                    ),
                    const SizedBox(height: 16),
                  ],

                  // Unlock/Create button
                  FilledButton.icon(
                    onPressed: vaultService.isLoading
                        ? null
                        : (_isCreatingVault ? _createVault : _unlock),
                    icon: vaultService.isLoading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : Icon(_isCreatingVault ? Icons.add : Icons.lock_open),
                    label: Text(_isCreatingVault ? 'Create Vault' : 'Unlock'),
                  ),
                  const SizedBox(height: 16),

                  // Toggle create/unlock mode
                  TextButton(
                    onPressed: () {
                      setState(() {
                        _isCreatingVault = !_isCreatingVault;
                        _passwordController.clear();
                        _confirmPasswordController.clear();
                      });
                    },
                    child: Text(
                      _isCreatingVault
                          ? 'Already have a vault? Unlock'
                          : 'New user? Create vault',
                    ),
                  ),

                  // Security note
                  const SizedBox(height: 48),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: colorScheme.surfaceContainerHighest.withOpacity(0.5),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          Icons.info_outline,
                          color: colorScheme.onSurfaceVariant,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            'Your vault is encrypted with AES-256-GCM. '
                            'Your password never leaves this device.',
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
          ),
        ),
      ),
    );
  }
}
