// Shell smoke tests.
//
// Only the parts that don't need native plugins are covered here. The WebView
// needs the WebView2 runtime, and the title bar's drag surface / caption
// buttons come from bitsdojo_window, which requires a real native window — so
// neither can be mounted in a widget test.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:aria_shell/main.dart';

void main() {
  test('backend URL points at the local Aria service', () {
    expect(kAriaUrl, 'http://127.0.0.1:8765');
  });

  test('chrome colours match the web UI palette', () {
    expect(kAccent, const Color(0xFF0369A1)); // security blue
    expect(kBg, const Color(0xFFFFFFFF)); // white, single theme
  });

  testWidgets('error pane explains the shell does not start the backend',
      (tester) async {
    var retried = false;
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: ErrorPane(
          message: 'WebView2 not found',
          onRetry: () => retried = true,
        ),
      ),
    ));

    expect(find.text("Can't reach the Aria service"), findsOneWidget);
    expect(find.textContaining('does not start the service'), findsOneWidget);
    expect(find.text('WebView2 not found'), findsOneWidget);

    await tester.tap(find.text('Retry'));
    await tester.pump();
    expect(retried, isTrue);
  });
}
