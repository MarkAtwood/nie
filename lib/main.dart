import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'src/rust/frb_generated.dart';
import 'src/services/identity_service.dart';
import 'src/services/relay_service.dart';
import 'app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the Rust FFI layer (sets up the tokio runtime and logcat on Android).
  await RustLib.init();

  runApp(
    MultiProvider(
      providers: [
        Provider<IdentityService>(create: (_) => IdentityService()),
        ChangeNotifierProvider<RelayService>(create: (_) => RelayService()),
      ],
      child: const NieApp(),
    ),
  );
}
