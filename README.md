This project contains a [Wireshark](https://www.wireshark.org/) dissector for [Syncthing](https://syncthing.net/) protocols. Currently, only Announcement packets ([Local Discovery Protocol v4](https://docs.syncthing.net/specs/localdisco-v4.html)) are supported.

## Usage

 * Copy `syncthing.lua` to one of Wireshark's `Lua Plugins` folders, as specified in `About / Folders`.
 * Copy `syncthing.proto` to any convenient location, and enter the location in `Preferences / Protocols / ProtoBuf / ProtoBuf search paths`.
 * If Wireshark is running, enter `ctrl` + `shift` + `l` to reload Lua plugins.
 
Wireshark should now automatically dissect Syncthing Announcement packets.
 
## Author

The author of this software is Thomas More.

## License

This software is licensed under the [Gnu General Public License version 2](https://www.gnu.org/licenses/gpl-2.0.html).
