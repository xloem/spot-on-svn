purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.freebsd.qt5.pro \
			Kernel/spot-on-kernel.freebsd.qt5.pro
TEMPLATE	=	subdirs
CONFIG		+=	ordered
