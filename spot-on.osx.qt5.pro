purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.osx.qt5.pro \
			Kernel/spot-on-kernel.osx.qt5.pro
TEMPLATE	=	subdirs
CONFIG		+=	ordered
