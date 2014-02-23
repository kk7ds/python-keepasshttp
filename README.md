# Python KeePassX HTTP Server

This is a standalone server to expose a KeePassX database over localhost like the
KeePassHTTP plugin for KeePass does. KeePass is a Windows application that supports
plugins, but which does not run well (or at least, natively) on Linux or MacOS.
KeePassX is an alternate implementation that is cross-platform, but does not
support plugins. This tool supports the KeePassHTTP protocol, but reads directly
from a KeePassX database.

Using this enables Chrome and Firefox plugins to auto-fill authentication forms
from your KeePassX database.

## Installation
 1. Get and install [python-keepass](https://github.com/brettviren/python-keepass)
 2. Run `python setup.py install`

## Usage
In order for the browser extension to talk to this server, you must first associate
it. Association should be done once and with care, as anyone who successfully
snoops the association exchange can snoop and read further passwords. So, the first
time you start the tool, pass the `-A` option to allow associations:

    keepass_server -a -A my_database.kdb

Then initiate the connection from the browser. Once the two are associated, stop
the keepass server and start it again with associations disabled:

    keepass_server -a my_database.kdb

## Testing
To run the tests:

    python setup.py test

## Caveats
 * Password generation/saving from the plugin side is not supported

## References
 * KeePassX: https://www.keepassx.org/
 * python-keepass: https://github.com/brettviren/python-keepass
 * Firefox/Chrome extensions: https://github.com/pfn/passifox/
 * Original Windows KeePass application: http://keepass.info/
 * Original KeePassHTTP plugin: https://github.com/pfn/keepasshttp
