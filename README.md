Parser and ffi generator for MS Windows
[`.winmd`](https://learn.microsoft.com/en-us/uwp/winrt-cref/winmd-files)
format metadata files (currently only tested with the
[`Win32`](https://github.com/microsoft/win32metadata) files, but
intended to eventually support `WinRT` and `Windows App SDK` as well.

### current status: proof-of-concept, not ready for use

Code is a big mess and needs lots of cleanup, but seems to parse
current `Windows.Win32.winmd` more or less correctly. Can generate
something resembling `cffi` and `com-on` ffi definitions, but not in a
directly usable form, and no actual user API yet. Probably missing a
few things, and might be getting some details wrong, but at least
looks close.
