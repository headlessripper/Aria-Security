// Aria Security — native Windows shell.
//
// Deliberately thin: a frameless window with a custom title bar that hosts the
// existing Aria UI (served by the Python backend on 127.0.0.1:8765) in a
// WebView2 view. No app logic lives here — the web UI and its REST/Socket.IO
// API remain the single source of truth.

import 'dart:async';

import 'package:bitsdojo_window/bitsdojo_window.dart';
import 'package:flutter/material.dart';
import 'package:webview_windows/webview_windows.dart';

/// Where the Python backend serves the UI.
const String kAriaUrl = 'http://127.0.0.1:8765';

/// Chrome colours — kept in step with the web UI's Soft-UI palette.
const Color kAccent = Color(0xFF0369A1); // security blue
const Color kBg = Color(0xFFFFFFFF);
const Color kBorder = Color(0xFFE2ECF4);
const Color kText = Color(0xFF0C2B3F);
const Color kDim = Color(0xFF55708A);

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AriaShellApp());

  // Frameless window sized like the previous pywebview window.
  doWhenWindowReady(() {
    appWindow
      ..minSize = const Size(940, 620)
      ..size = const Size(1280, 820)
      ..alignment = Alignment.center
      ..title = 'Aria Security'
      ..show();
  });
}

class AriaShellApp extends StatelessWidget {
  const AriaShellApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Aria Security',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: kAccent),
        scaffoldBackgroundColor: kBg,
      ),
      home: const ShellWindow(),
    );
  }
}

class ShellWindow extends StatefulWidget {
  const ShellWindow({super.key});

  @override
  State<ShellWindow> createState() => _ShellWindowState();
}

class _ShellWindowState extends State<ShellWindow> {
  final _controller = WebviewController();
  bool _ready = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    try {
      await _controller.initialize();
      await _controller.setBackgroundColor(kBg);
      await _controller.setPopupWindowPolicy(WebviewPopupWindowPolicy.deny);
      await _controller.loadUrl(kAriaUrl);
      if (!mounted) return;
      setState(() => _ready = true);
    } catch (e) {
      if (!mounted) return;
      // Most commonly: the WebView2 runtime is missing, or the backend is down.
      setState(() => _error = e.toString());
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          const TitleBar(),
          Expanded(child: _body()),
        ],
      ),
    );
  }

  Widget _body() {
    if (_error != null) return ErrorPane(message: _error!, onRetry: _retry);
    if (!_ready) {
      return const Center(
        child: SizedBox(
          width: 26,
          height: 26,
          child: CircularProgressIndicator(strokeWidth: 2.5, color: kAccent),
        ),
      );
    }
    return Webview(_controller);
  }

  void _retry() {
    setState(() {
      _error = null;
      _ready = false;
    });
    _init();
  }
}

/// Frameless-window chrome: draggable strip + minimise / maximise / close.
class TitleBar extends StatelessWidget {
  const TitleBar({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 40,
      decoration: const BoxDecoration(
        color: kBg,
        border: Border(bottom: BorderSide(color: kBorder)),
      ),
      child: Row(
        children: [
          const SizedBox(width: 12),
          Container(
            width: 22,
            height: 22,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF0EA5E9), kAccent],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(7),
            ),
            child: const Icon(Icons.shield, size: 13, color: Colors.white),
          ),
          const SizedBox(width: 10),
          const Text(
            'Aria Security',
            style: TextStyle(
              fontSize: 12.5,
              fontWeight: FontWeight.w600,
              color: kText,
              letterSpacing: .2,
            ),
          ),
          // Everything else is drag surface.
          Expanded(child: MoveWindow()),
          const _WindowButtons(),
        ],
      ),
    );
  }
}

class _WindowButtons extends StatelessWidget {
  const _WindowButtons();

  @override
  Widget build(BuildContext context) {
    final colors = WindowButtonColors(
      iconNormal: kDim,
      iconMouseOver: kText,
      mouseOver: const Color(0xFFF4F9FD),
      mouseDown: const Color(0xFFEAF3FA),
    );
    final closeColors = WindowButtonColors(
      iconNormal: kDim,
      iconMouseOver: Colors.white,
      mouseOver: const Color(0xFFDC2626),
      mouseDown: const Color(0xFFB91C1C),
    );
    return Row(
      children: [
        MinimizeWindowButton(colors: colors),
        MaximizeWindowButton(colors: colors),
        CloseWindowButton(colors: closeColors),
      ],
    );
  }
}

/// Shown when the WebView can't start or the backend isn't reachable.
class ErrorPane extends StatelessWidget {
  const ErrorPane(
      {super.key, required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.wifi_off_rounded, size: 34, color: kDim),
            const SizedBox(height: 14),
            const Text(
              "Can't reach the Aria service",
              style: TextStyle(
                  fontSize: 15, fontWeight: FontWeight.w600, color: kText),
            ),
            const SizedBox(height: 8),
            const Text(
              'Make sure the Aria backend is running on 127.0.0.1:8765.\n'
              'This shell only displays the UI — it does not start the service.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12.5, color: kDim, height: 1.5),
            ),
            const SizedBox(height: 18),
            FilledButton(
              onPressed: onRetry,
              style: FilledButton.styleFrom(
                backgroundColor: kAccent,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10)),
              ),
              child: const Text('Retry'),
            ),
            const SizedBox(height: 14),
            SelectableText(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 11, color: Color(0xFF93A9BD)),
            ),
          ],
        ),
      ),
    );
  }
}
