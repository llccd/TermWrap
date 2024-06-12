# TermWrap

My rewrite of [rdpwrap](https://github.com/stascorp/rdpwrap)

## Compared to original rdpwrap

1. Only support x64-based systems starting from Vista

2. Integrated [RDPWrapOffsetFinder](https://github.com/llccd/RDPWrapOffsetFinder), patch offsets are automatically searched, and will survive after installing updates

3. Improved SingleUserPatch which respects fSingleSessionPerUser registry setting

4. Enabled camera and USB redirection for all SKUs by additional wrap of UmRdpService

## Usage

### Install

First, ensure [Microsoft Visual C++ 2015-2022 Redistributable (x64)](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist) is installed

Copy 3 dlls to "%ProgramFiles%\RDP Wrapper\" and merge "Install.reg", then reboot system

### Uninstall

Merge "Revert_to_default.reg" and reboot system, then delete files in "%ProgramFiles%\RDP Wrapper\"

### Enable USB redirection

To enable remote desktop USB redirection, additional group policy settings are required:

`Computer Configuration\Administrative Templates\System\Device Installation\Allow remote access to the Plug and Play interface` -> Enabled

`Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow supported Plug and Play device redirection` -> Disabled

`Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client\RemoteFX USB Device Redirection\Allow RDP redirection of other supported RemoteFX USB devices from this computer` -> Enabled
