purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.qt5.pro \
			Kernel/spot-on-kernel.qt5.pro
TEMPLATE	=	subdirs
CONFIG		+=	ordered
