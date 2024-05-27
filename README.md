A (mostly complete) [Wireshark](https://www.wireshark.org/) Lua plugin with submodules that passively analyzes network traffic to determine OS info from the corresponding packets. Tested with Wireshark v3.6.2 and Wireshark v4.2.x.

(**[NOTE (27/5/2024)]:** This codebase is still a work in progress and at an experimental stage. *I don't recommend using this plugin in production yet*).

This plugin makes use of various XML fingerprints from [`xnih`'s implementation of Satori](https://github.com/xnih/satori) to guess OS info from network traffic, whether it's a live capture or an offline capture. Because of that, this plugin is (at least) a partial Lua clone of `xnih`'s Satori with some [NetworkMiner's snippets](https://www.netresec.com/?page=NetworkMiner) adapted into Lua code.

## Dependencies ##
This plugin needs the following requirements in order to properly work:
- Lua 5.2
- LuaRocks
  - `luarocks`packages needed (all for Lua **5.2**):
    - [inspect](https://luarocks.org/modules/kikito/inspect)
    - [lua-cjson](https://luarocks.org/modules/openresty/lua-cjson)
    - [md5](https://luarocks.org/modules/tomasguisasola/md5)
    - [xml2lua](https://luarocks.org/modules/tomasguisasola/md5)
