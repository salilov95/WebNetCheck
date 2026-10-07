# Third-party notices

## web-netcheck

WebNetCheck is an independent Windows implementation of the idea behind
[nimbo78/web-netcheck](https://github.com/nimbo78/web-netcheck). No code was copied, but the
built-in profiles (`profiles/github.toml`, `profiles/ya.toml`, `profiles/zai.toml`) are
derived from the host lists and probe definitions of that project, which is distributed
under the following license:

```
MIT License

Copyright (c) 2026 nimbo78

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Runtime dependencies

Installed from PyPI, not vendored in this repository. The prebuilt exe bundles them.

| Package | License |
|---|---|
| [PySide6](https://pypi.org/project/PySide6/) (Qt for Python) | LGPL-3.0 (alternatively GPL or commercial) |
| [dnspython](https://pypi.org/project/dnspython/) | ISC |
| [cryptography](https://pypi.org/project/cryptography/) | Apache-2.0 OR BSD-3-Clause |

The exe is built in PyInstaller one-folder mode: Qt and PySide6 stay as separate DLL files in
`_internal\`, so they can be replaced with other builds of the same libraries, as LGPL requires.
