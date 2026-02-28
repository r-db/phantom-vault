import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'core/services/vault_service.dart';
import 'core/services/theme_service.dart';
import 'features/unlock/unlock_screen.dart';
import 'features/secrets_list/secrets_list_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const VaultSecretsApp());
}

class VaultSecretsApp extends StatelessWidget {
  const VaultSecretsApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => VaultService()),
        ChangeNotifierProvider(create: (_) => ThemeService()),
      ],
      child: Consumer<ThemeService>(
        builder: (context, themeService, _) {
          return MaterialApp(
            title: 'Vault Secrets',
            debugShowCheckedModeBanner: false,
            theme: themeService.lightTheme,
            darkTheme: themeService.darkTheme,
            themeMode: themeService.themeMode,
            home: const VaultRouter(),
          );
        },
      ),
    );
  }
}

/// Routes to unlock or secrets list based on vault state
class VaultRouter extends StatelessWidget {
  const VaultRouter({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<VaultService>(
      builder: (context, vaultService, _) {
        if (vaultService.isUnlocked) {
          return const SecretsListScreen();
        }
        return const UnlockScreen();
      },
    );
  }
}
