import 'package:flutter/material.dart';
import 'src/screens/setup_screen.dart';

class NieApp extends StatelessWidget {
  const NieApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'nie',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: const SetupScreen(),
    );
  }
}
