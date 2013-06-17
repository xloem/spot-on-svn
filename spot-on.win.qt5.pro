purge.commands = del /F *\\*~ && del /F *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.win.qt5.pro \
			Kernel\\spot-on-kernel.win.qt5.pro
TEMPLATE	=	subdirs
CONFIG		+=	ordered
