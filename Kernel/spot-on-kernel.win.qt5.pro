cache()
libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\..\\libSpotOn
libspoton.depends =
purge.commands = del /F *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
QT		-= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_LINKED_WITH_LIBGEOIP

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += ..\\..\\release\\Spot-On-Kernel \
		   ..\\..\\..\\libSpotOn\\libspoton.dll \
		   ..\\..\\..\\libSpotOn\\*.o ..\\..\\..\\libSpotOn\\test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -mtune=generic -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector
QMAKE_DISTCLEAN	+= .qmake.cache
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ..\\. ..\\..\\..\\. ..\\..\\..\\libSpotOn\\Include.win32 \
                   ..\\..\\..\\libGeoIP\\Include.win32 \
		   ..\\..\\..\\libOpenSsl\\Include.win32
LIBS		+= -L..\\..\\..\\libSpotOn \
		   -L..\\..\\..\\libSpotOn\\Libraries.win32 \
                   -L..\\..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\..\\libOpenSsl\\Libraries.win32 \
		   -lGeoIP-1 -leay32 -lgcrypt-11 -lpthread -lspoton -lssl32
PRE_TARGETDEPS = libspoton.dll

HEADERS		= ..\\Common\\spot-on-external-address.h \
		  spot-on-gui-server.h \
		  spot-on-kernel.h \
		  spot-on-listener.h \
		  spot-on-mailer.h \
		  spot-on-neighbor.h \
		  spot-on-shared-reader.h

SOURCES		= ..\\Common\spot-on-crypt.cc \
		  ..\\Common\\spot-on-external-address.cc \
		  ..\\Common\\spot-on-misc.cc \
		  ..\\Common\\spot-on-send.cc \
		  spot-on-gui-server.cc \
		  spot-on-kernel.cc \
		  spot-on-listener.cc \
		  spot-on-mailer.cc \
		  spot-on-neighbor.cc \
		  spot-on-shared-reader.cc

TRANSLATIONS    =

TARGET		= ..\\..\\release\\Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel

spoton_kernel.path	= ..\\release
spoton_kernel.files	= Spot-On-Kernel.exe
libgeoip_install.path   = ..\\release
libgeoip_install.files  = ..\\..\\..\\libGeoIP\\Libraries.win32\\libGeoIP-1.dll
libspoton_install.path  = ..\\release
libspoton_install.files = ..\\..\\..\\libSpotOn\\libspoton.dll ..\\..\\..\\libSpotOn\\Libraries.win32\\*.def ..\\..\\..\\libSpotOn\\Libraries.win32\\*.dll

INSTALLS	= libgeoip_install \
                  libspoton_install \
                  spoton_kernel
