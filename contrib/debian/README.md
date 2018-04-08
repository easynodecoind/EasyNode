
Debian
====================
This directory contains files used to package easynoded/easynode-qt
for Debian-based Linux systems. If you compile easynoded/easynode-qt yourself, there are some useful files here.

## easynode: URI support ##


easynode-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install easynode-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your easynode-qt binary to `/usr/bin`
and the `../../share/pixmaps/easynode128.png` to `/usr/share/pixmaps`

easynode-qt.protocol (KDE)

