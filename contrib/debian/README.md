
Debian
====================
This directory contains files used to package 401kcoind/401kcoin-qt
for Debian-based Linux systems. If you compile 401kcoind/401kcoin-qt yourself, there are some useful files here.

## 401kcoin: URI support ##


401kcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install 401kcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your 401kcoinqt binary to `/usr/bin`
and the `../../share/pixmaps/401kcoin128.png` to `/usr/share/pixmaps`

401kcoin-qt.protocol (KDE)

