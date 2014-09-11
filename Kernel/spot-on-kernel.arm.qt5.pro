cache()
libspoton.target = libspoton.so
libspoton.commands = $(MAKE) -C ../../../libSpotOn library
libspoton.depends =
purge.commands = rm -f *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= concurrent core network sql
QT		-= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += ../Spot-On-Kernel ../../../libSpotOn/*.o \
		   ../../../libSpotOn/*.so ../../../libSpotOn/test
QMAKE_DISTCLEAN += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra -Wl,-z,relro \
			  -Woverloaded-virtual -Wpointer-arith \
                          -Wstack-protector -Wstrict-overflow=4
QMAKE_LFLAGS_RELEASE += -Wl,-rpath,/usr/local/spot-on/Lib -L/usr/local/lib
QMAKE_EXTRA_TARGETS = libspoton purge
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= /usr/include . ../. ../../../.
LIBS		+= -L../../../libSpotOn -L/usr/local/lib \
		   -lcrypto -lgcrypt -lgpg-error -lssl
PRE_TARGETDEPS = libspoton.so
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

HEADERS		= ../Common/spot-on-external-address.h \
		  spot-on-gui-server.h \
		  spot-on-kernel.h \
		  spot-on-listener.h \
		  spot-on-mailer.h \
		  spot-on-neighbor.h \
		  spot-on-sctp-server.h \
		  spot-on-sctp-socket.h \
		  spot-on-shared-reader.h \
		  spot-on-starbeam-reader.h \
		  spot-on-starbeam-writer.h

SOURCES		= ../Common/spot-on-crypt.cc \
		  ../Common/spot-on-external-address.cc \
		  ../Common/spot-on-misc.cc \
		  ../Common/spot-on-send.cc \
		  spot-on-gui-server.cc \
		  spot-on-kernel.cc \
		  spot-on-listener.cc \
		  spot-on-mailer.cc \
		  spot-on-neighbor.cc \
		  spot-on-sctp-server.cc \
		  spot-on-sctp-socket.cc \
		  spot-on-shared-reader.cc \
		  spot-on-starbeam-reader.cc \
		  spot-on-starbeam-writer.cc

TRANSLATIONS    =

TARGET		= ../Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
