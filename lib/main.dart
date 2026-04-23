import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'src/services/identity_service.dart';
import 'src/services/relay_service.dart';
import 'app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider<IdentityService>(create: (_) => IdentityService()),
        ChangeNotifierProvider<RelayService>(create: (_) => RelayService()),
      ],
      child: const NieApp(),
    ),
  );
}
