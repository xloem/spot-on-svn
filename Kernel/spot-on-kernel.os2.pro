libspoton.target = libspotn.dll
libspoton.commands = $(MAKE) -C ../../../libSpotOn
libspoton.depends =
purge.commands = del /F *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
QT		-= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         -= SPOTON_LINKED_WITH_LIBGEOIP

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += ../../release/Spot-On-Kernel \
		   ../../../libSpotOn/libspotn.dll \
		   ../../../libSpotOn/*.o ../../../libSpotOn/test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -mtune=generic -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ../. ../../../. ../../../libSpotOn/Include.win32 \
		   u:/usr/local473/include
LIBS		+= -L../../../libSpotOn \
		   -L../../../libSpotOn/Libraries.win32 \
		   -Lu:/usr/local473/lib \
		   -lcrypto -lgcrypt -lgpg-error -lmmap -lpthread -lspoton \
		   -lssl -lssp_s
PRE_TARGETDEPS = libspotn.dll

HEADERS		= ../Common/spot-on-external-address.h \
		  spot-on-gui-server.h \
		  spot-on-kernel.h \
		  spot-on-listener.h \
		  spot-on-mailer.h \
		  spot-on-neighbor.h \
		  spot-on-shared-reader.h

SOURCES		= ../Common/spot-on-crypt.cc \
		  ../Common/spot-on-external-address.cc \
		  ../Common/spot-on-misc.cc \
		  ../Common/spot-on-send.cc \
		  spot-on-gui-server.cc \
		  spot-on-kernel.cc \
		  spot-on-listener.cc \
		  spot-on-mailer.cc \
		  spot-on-neighbor.cc \
		  spot-on-shared-reader.cc

TRANSLATIONS    =

TARGET		= Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel
