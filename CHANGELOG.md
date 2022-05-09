# Project History

## 0.0.8

(Released on 2022-05-09)

* Fixed a gradual memory leak.
* PIN prompt window can now time out and disappear on its own after
  a few seconds of inactivity. Before, it was possible for the PIN
  prompt window to be retained on screen indefinitely.
* The connection to the YubiKey is now dropped after 60 minutes of
  inactivity. This shores up security a bit, as it limits how long
  the YubiKey can be in an authenticated state.

## 0.0.7

(Released on 2022-04-27)

* Refactored GUI internals so we have more control over low-level
  startup functionality. This shouldn't have changed any behavior.
  But it wouldn't be surprising if it did.
* There is now a system tray menu item to reflect whether the agent
  is installed via `SSH_AUTH_SOCK`. If it isn't, you can click the
  menu item to replace `SSH_AUTH_SOCK` with this daemon's socket.
* Fixed a race condition on app startup that could result in a crash.
* Significant changes to PIN prompt window. It should now appear
  under the tray icon. It has no window decorations. Context that
  was displayed in addition to the PIN prompt has been removed because
  it is redundant with what's available in the tray menu.

## 0.0.6

(Released on 2022-04-25)

* Application icon no longer appears in macOS dock.

## 0.0.5

(Released on 2022-04-25)

* Removed notifications. With the PIN prompt window being hidden by
  default and being very visible when it appears, we don't believe
  notifications are providing any meaningful value. So they have
  been removed.
* macOS application is now distributed as a bundle, not a standalone
  executable.

## 0.0.4

(Released on 2022-04-25)

* Added a status bar icon on macOS. It has a menu exposing state and
  allows you to exit the application.
* Removed support for binding agent to a TCP address.
* `--socket` argument is no longer required and the application will bind
  to a socket in a default path by default.

## 0.0.3

(Released on 2022-04-21)

* The PIN prompt window now steals focus when it appears.
* Window decorations are restored (enables moving window again).
* Added a button to the GUI to deny PIN entry.

## 0.0.2

(Released on 2022-04-21)

* Window is hidden by default.
* Window appears when a device unlock is needed.
* Window disappears automatically after PIN operation.
* PIN prompt window always appears on top of other windows.
* Window doesn't have OS decorations and is more minimal.

## 0.0.1

(Released on 2022-04-20)

* Initial version.
