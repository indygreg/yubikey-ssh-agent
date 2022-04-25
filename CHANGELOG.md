# Project History

## 0.0.5

(Not yet released)

* Removed notifications. With the PIN prompt window being hidden by
  default and being very visible when it appears, we don't believe
  notifications are providing any meaningful value. So they have
  been removed.

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
