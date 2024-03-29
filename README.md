# android_ebpf

android ebpf dev tools and notes

## tested env

- Android 10 arm64
## install termux.apk

```
% gh run list --repo termux/termux-app -L 5
STATUS  NAME                                                              WORKFLOW                 BRANCH  EVENT  ID          ELAPSED  AGE
✓       Added: Start termux app docs support at https://termux.dev/do...  Build                    master  push   2532010124  3m49s    14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Unit tests               master  push   2532010122  2m35s    14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Validate Gradle Wrapper  master  push   2532010120  18s      14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Validate Gradle Wrapper  master  push   2531825064  17s      14d
✓       Added: Start termux app docs support at https://termux.dev/do...  Build                    master  push   2531825063  4m37s    14d

% gh run download 2532010124 -p "*android-7-github-debug_arm64-v8a" --repo termux/termux-app
% adb install -r termux*.apk
```

## make run-as-termux.sh

```
walleye:/ #adb shell
walleye:/ #cat /data/local/tmp/run-as-termux.sh
#!/bin/sh

# Add this file on you /sdcard directory on you android Phone
# Enable Debug Mode and ADB, connect you phone on PC, Download ADB Tools
# Run "adb shell" and on adb shell run "sh /sdcard/run-as-termux.sh"
# Enjoy termux, but with restrictions to access some folders like /sdcard

TERMUX_PACKAGE=com.termux
TERMUX_PATH=$ANDROID_DATA/data/$TERMUX_PACKAGE
TERMUX_TMPDIR=$TERMUX_PATH/files/usr/tmp
FNAME=$TERMUX_TMPDIR/$TERMUX_PACKAGE-$$
SCRIPT=$FNAME.sh
RCFILE=$FNAME.bashrc
ENVFILE=$FNAME.env
INITFILE=$FNAME.init
TERMUX_BASH=$TERMUX_PATH/files/usr/bin/bash
export TERMUX_PACKAGE TERMUX_PATH TERMUX_TMPDIR SCRIPT RCFILE ENVFILE INITFILE TERMUX_BASH

run-as $TERMUX_PACKAGE sh -c "cat > $ENVFILE" <<EOF
TERMUX_PACKAGE=$TERMUX_PACKAGE
TERMUX_PATH=$TERMUX_PATH
TERMUX_UID=$TERMUX_UID
TERMUX_APP_PID=$TERMUX_APP_PID
TMPDIR=$TERMUX_TMPDIR
SHELL=$TERMUX_PATH/files/usr/bin/bash
COLORTERM=truecolor
HISTCONTROL=ignoreboth
PREFIX=$TERMUX_PATH/files/usr
TERMUX_IS_DEBUGGABLE_BUILD=1
TERMUX_VERSION=0.118.0
LD_PRELOAD=$TERMUX_PATH/files/usr/lib/libtermux-exec.so
HOME=$TERMUX_PATH/files/home
LANG=en_US.UTF-8
TERMUX_APK_RELEASE=GITHUB
TERM=xterm-256color
SHLVL=1
PATH=$TERMUX_PATH/files/usr/bin
EOF

run-as $TERMUX_PACKAGE sh -c "cat > $RCFILE" <<EOF
#!$TERMUX_BASH
rm -f $RCFILE > /dev/null 2>&1
unset RCFILE > /dev/null 2>&1
. $ENVFILE
if [[ "\$(echo \$TERMUX_UID | xargs)" == "" ]]; then
	TERMUX_UID=\$(cmd package list packages -U $TERMUX_PACKAGE | rev | cut -d':' -f1 | rev)
fi
if [[ "\$(echo \$TERMUX_APP_PID | xargs)" == "" ]]; then
	TERMUX_APP_PID=\$(pgrep -o -u \$TERMUX_UID | xargs)
	if [[ "\$(echo \$TERMUX_APP_PID | xargs)" == "" ]]; then
		TERMUX_APP_PID=\$\$
	fi
fi
export TERMUX_PACKAGE TERMUX_PATH TERMUX_UID TERMUX_APP_PID TMPDIR SHELL COLORTERM HISTCONTROL PREFIX TERMUX_IS_DEBUGGABLE_BUILD TERMUX_VERSION LD_PRELOAD HOME LANG TERMUX_APK_RELEASE TERM SHLVL PATH
APP_ENV=/proc/\$(pgrep -o -P \$TERMUX_APP_PID)/environ
if [ -f \$APP_ENV ]; then
	. \$APP_ENV
fi
rm -f $ENVFILE > /dev/null 2>&1
unset ENVFILE > /dev/null 2>&1
EOF

run-as $TERMUX_PACKAGE sh -c "cat > $INITFILE" <<EOF
#!$TERMUX_BASH
rm -f $INITFILE > /dev/null 2>&1
unset INITFILE > /dev/null 2>&1
. $RCFILE
cd ~
EOF

run-as $TERMUX_PACKAGE sh -c "cat > $SCRIPT" <<EOF
#!/bin/sh
rm -f $SCRIPT
unset SCRIPT > /dev/null 2>&1
[[ -x $TERMUX_BASH ]] && $TERMUX_BASH --rcfile $RCFILE --init-file $INITFILE $@
rm -f $RCFILE $ENVFILE $INITFILE > /dev/null 2>&1
unset RCFILE ENVFILE INITFILE > /dev/null 2>&1
EOF

run-as $TERMUX_PACKAGE chmod +x $SCRIPT $RCFILE $ENVFILE $INITFILE
run-as $TERMUX_PACKAGE $SCRIPT
run-as $TERMUX_PACKAGE rm -f $SCRIPT $RCFILE $ENVFILE $INITFILE > /dev/null 2>&1
unset TERMUX_PACKAGE TERMUX_PATH TERMUX_TMPDIR FNAME SCRIPT RCFILE ENVFILE INITFILE TERMUX_BASH > /dev/null 2>&1
```

## install proot env

```
# /data/local/tmp/run-as-termux.sh
######################### 还是不要改了，国内基本没有arm64的Ubuntu binary-arm64/Packages mirror
# Tsinghua mirror
# https://mirrors.ustc.edu.cn/repogen/
~ $ termux-change-repo
#############################################################


# Install proot-distro
~ $ apt update && apt install -y proot-distro

# https://www.jianshu.com/p/e9873d92ebbd
# http://security.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20211016_all.deb
# http://ports.ubuntu.com/pool/main/o/openssl/openssl_3.0.2-0ubuntu1_arm64.deb
~ $ proot-distro install ubuntu
~ $ proot-distro login ubuntu

# https://forums.kali.org/showthread.php?48217-SSH-Bash-Required-key-not-available
# commented out the line "session optional pam_keyinit.so force revoke" in all the files under "/etc/pam.d/":
root@localhost:/etc/apt# uname -a
Linux localhost 5.4.0-faked #1 SMP PREEMPT Tue Mar 30 05:16:27 UTC 2021 aarch64 aarch64 aarch64 GNU/Linux
root@localhost:/# vim /etc/pam.d/su-l
root@localhost:/# vim /etc/pam.d/login
root@localhost:/# vim /etc/pam.d/runuser-l
root@localhost:/# exit

# need relogin
~ $ proot-distro login ubuntu
root@localhost:/# apt install ca-certificates  apt-transport-https wget gnupg curl lsb-release bcc python3-bpfcc python3 python3-pip -y
root@localhost:/# awget https://github.com/iovisor/bcc/raw/master/tools/execsnoop.py
root@localhost:/# chmod a+x execsnoop.py
# https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary
root@localhost:/# apt install sudo bpftrace bpftool bcc bpfcc-tools linux-headers-$(uname -r)
```

##  sources.list of proot env

ubuntu:

```
# cat /etc/apt/sources.list
deb [signed-by="/usr/share/keyrings/ubuntu-archive-keyring.gpg"] http://ports.ubuntu.com/ubuntu-ports jammy main universe multiverse
deb [signed-by="/usr/share/keyrings/ubuntu-archive-keyring.gpg"] http://ports.ubuntu.com/ubuntu-ports jammy-updates main universe multiverse
deb [signed-by="/usr/share/keyrings/ubuntu-archive-keyring.gpg"] http://ports.ubuntu.com/ubuntu-ports jammy-security main universe multiverse
```

debian:

```
# cat /etc/apt/sources.list
deb [signed-by="/usr/share/keyrings/debian-archive-keyring.gpg"] http://deb.debian.org/debian bullseye main contrib
deb [signed-by="/usr/share/keyrings/debian-archive-keyring.gpg"] http://deb.debian.org/debian bullseye-updates main contrib
deb [signed-by="/usr/share/keyrings/debian-archive-keyring.gpg"] http://security.debian.org/debian-security bullseye-security main contrib
```

## patch android kernel

TBD

## test

TBD

## ref

https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md

https://bowers.github.io/eBPF-Hello-World/

https://ubuntu.pkgs.org/20.04/ubuntu-updates-main-arm64/linux-headers-5.4.0-92-generic_5.4.0-92.103_arm64.deb.html
http://ports.ubuntu.com/pool/main/l/linux/linux-headers-5.4.0-92-generic_5.4.0-92.103_arm64.deb
https://ubuntu.pkgs.org/20.04/ubuntu-updates-main-arm64/linux-headers-5.4.0-92_5.4.0-92.103_all.deb.html
http://ports.ubuntu.com/pool/main/l/linux/linux-headers-5.4.0-92_5.4.0-92.103_all.deb

https://source.android.com/devices/architecture/kernel/bpf

https://github.com/libbpf/libbpf/blob/master/.github/actions/vmtest/action.yml

https://www.aisp.sg/cyberfest/document/CRESTConSpeaker/eBPF.pdf

https://gist.github.com/goisneto/4e0a9c7c8cf6f6fc86fb96b454384c57

https://github.com/tiann/eadb
