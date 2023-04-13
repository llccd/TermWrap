# TermWrap

My rewrite of [rdpwrap](https://github.com/stascorp/rdpwrap)

## Compared to original rdpwrap

1. Only support x64-based systems and patch process mainly focus on win10/11 (TermWrap still works on older x64 systems starting from vista)

2. Integrated [RDPWrapOffsetFinder](https://github.com/llccd/RDPWrapOffsetFinder), patch offsets are automatically calculated, no annoying ini update anymore

3. Fixed incorrect SingleUserPatch that prevents same user have multiple session simultaneously

4. Enabled camera and USB redirection for all SKUs by additional wrap of UmRdpService (UmWrap works on win8 and newer systems)

## Usage

### Install

First, ensure "Microsoft Visual C++ Redistributable Package 2015-2022 (x64)" is installed

Copy 3 dlls to "%ProgramFiles%\RDP Wrapper\" and merge "install.reg", then reboot system

### Uninstall

Merge "uninstall.reg" and reboot system, then delete files in "%ProgramFiles%\RDP Wrapper\"
