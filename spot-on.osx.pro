purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.osx.pro \
			Kernel/spot-on-kernel.osx.pro
TEMPLATE	=	subdirs

