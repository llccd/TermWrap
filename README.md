# TermWrap

My rewrite of [rdpwrap](https://github.com/stascorp/rdpwrap)

## Compared to original rdpwrap

1. Dropped x86 and older version that no longer reveive updates, mainly focus on win10/11 x64 support

2. Integrated [RDPWrapOffsetFinder](https://github.com/llccd/RDPWrapOffsetFinder), patch offsets are automatically calculated, no rdpwrap.ini anymore

3. Fixed incorrect SingleUserPatch that prevents same user have multiple session simultaneously

4. Enabled camera and USB redirection of all SKUs

## Usage

### Install

First, ensure "Microsoft Visual C++ Redistributable Package 2015-2022 (x64)" is installed

Copy 3 dlls to "%ProgramFiles%\RDP Wrapper\" and merge "install.reg", then reboot system

### Uninstall

Merge "uninstall.reg" and reboot system, then delete 3 dlls