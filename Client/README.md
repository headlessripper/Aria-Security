# Aria Security — Windows Shell (Flutter)

A thin native Windows shell that displays the Aria UI (`http://127.0.0.1:8765`)
in a WebView2 view inside a **frameless window with a custom title bar**.

This is **not** a rewrite of the UI. All app logic, pages and state stay in the
existing web UI and its REST/Socket.IO API. The shell only provides the window.

## What it does

- Frameless window (`bitsdojo_window`) with a custom title bar: app mark,
  "Aria Security", drag-to-move, snap, and minimise / maximise / close buttons
  styled to match the web UI's palette (close goes red on hover).
- Hosts the UI with `webview_windows` (WebView2), popups denied, white
  background to avoid a flash on load.
- If the backend isn't reachable it shows a "Can't reach the Aria service"
  pane with a **Retry** button instead of a blank window.

## Requirements

- Flutter SDK (Windows desktop enabled) — installed at `C:\src\flutter`.
- **WebView2 Runtime** — preinstalled on Windows 11; ships with most Win10
  builds. Install the Evergreen runtime if the shell reports a WebView error.
- The Aria Python backend must already be serving `127.0.0.1:8765`.
  **The shell does not start the backend** — run it as you do today.

## Run / build

```bash
cd Client
flutter pub get
flutter run  -d windows          # development
flutter build windows --release  # release build
```

Release output: `build\windows\x64\runner\Release\aria_shell.exe`
(build artifacts are git-ignored — never commit the `.exe`; the Aria scanner
quarantines PE bytes found inside `.git`).

## Configuration

The backend URL is a single constant at the top of `lib/main.dart`:

```dart
const String kAriaUrl = 'http://127.0.0.1:8765';
```

The title-bar colours mirror the web UI's Soft-UI palette (`kAccent` =
`#0369A1`); keep them in step if the web theme changes.

## Notes

- `windows/runner/main.cpp` is patched with
  `bitsdojo_window_configure(BDW_CUSTOM_FRAME | BDW_HIDE_ON_STARTUP)` — required
  for the frameless window. Re-apply it if the runner is ever regenerated.
- Because this is only a shell, the two processes are independent: the backend
  can be restarted without touching the shell, and vice versa.
