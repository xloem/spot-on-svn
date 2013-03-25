libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\..\\LibSpotOn
libspoton.depends =
purge.commands = del /F *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
QT		-= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_MINIMUM_GCRYPT_VERSION=0x010500

# Unfortunately, the clean target assumes too much knowledge
# about the internals of LibSpotOn.

QMAKE_CLEAN     += ..\\..\\release\\Spot-On-Kernel ..\\..\\..\\LibSpotOn\\*.dll \
		   ..\\..\\..\\LibSpotOn\\*.o ..\\..\\..\\LibSpotOn\\test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -mtune=generic -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ..\\. ..\\..\\..\\. ..\\..\\..\\LibSpotOn\\Include.win32
LIBS		+= -L..\\..\\..\\LibSpotOn -L..\\..\\..\\LibSpotOn\\Libraries.win32 \
		   -lgcrypt-11 -lpthread -lspoton
PRE_TARGETDEPS = libspoton.dll

HEADERS		= spot-on-gui-server.h \
		  spot-on-kernel.h \
		  spot-on-listener.h \
		  spot-on-neighbor.h

SOURCES		= ..\\Common\\spot-on-gcrypt.cc \
		  ..\\Common\\spot-on-misc.cc \
		  ..\\Common\\spot-on-send.cc \
		  spot-on-gui-server.cc \
		  spot-on-kernel.cc \
		  spot-on-listener.cc \
		  spot-on-neighbor.cc

TRANSLATIONS    =

TARGET		= ..\\..\\release\\Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel

spoton_kernel.path	= ..\\..\\release
spoton_kernel.files	= Spot-On-Kernel.exe
libgeoip_install.path   = ..\\..\\release
libgeoip_install.extra  = ..\\..\\..\\libGeoIP\\Libraries.win32\\libGeoIP-1.dll
libspoton_install.path  = ..\\..\\release
libspoton_install.extra = ..\\..\\..\\LibSpotOn\\libspoton.dll ..\\..\\..\\LibSpotOn\\Libraries.win32\\*.dll

INSTALLS	= libgeoip_install \
                  libspoton_install \
                  spoton_kernel
