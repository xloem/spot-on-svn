libspoton.target = libspoton.dylib
libspoton.commands = $(MAKE) -C ../../../libSpotOn
libspoton.depends =
purge.commands = rm -f *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
QT		-= gui
CONFIG		+= qt debug warn_on app_bundle

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_GEOIP_DATA_FILE="'\"/Applications/Spot-On.d/Data/GeoIP.dat\"'" \
	   SPOTON_LINKED_WITH_LIBGEOIP

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += ../Spot-On-Kernel ../../../libSpotOn/*.dylib \
		   ../../../libSpotOn/*.o ../../../libSpotOn/test
QMAKE_DISTCLEAN += -r temp
QMAKE_CXXFLAGS_DEBUG -= -O2
QMAKE_CXXFLAGS_DEBUG += -fPIE -fstack-protector-all -mtune=generic -pie -Os \
			-Wall -Wcast-align -Wcast-qual \
                        -Werror -Wextra \
			-Woverloaded-virtual -Wpointer-arith \
			-Wstack-protector
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -mtune=generic -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
                          -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector
QMAKE_EXTRA_TARGETS = libspoton purge
QMAKE_LFLAGS_RELEASE =
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= . ../. ../../../. ../../../libGeoIP/Include.osx64 \
                   /usr/local/include
ICON		=
LIBS		+= -L../../../libSpotOn -L/usr/local/lib -lcrypto -lgcrypt -lspoton \
                   -L../../../libGeoIP/Libraries.osx64 -lGeoIP
PRE_TARGETDEPS = libspoton.dylib
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

TARGET		= ../Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

spoton.path		= /Applications/Spot-On.d/Spot-On-Kernel.app
spoton.files		= ../Spot-On-Kernel.app/*
libgeoip_data_install.path = /Applications/Spot-On.d/Data
libgeoip_data_install.files = ../../../GeoIP-1.5.1/data/GeoIP.dat
libgeoip_install.path  = .
libgeoip_install.extra = cp ../../../libGeoIP/Libraries.osx64/libGeoIP.1.dylib ../Spot-On-Kernel.app/Contents/Frameworks/libGeoIP.1.dylib && install_name_tool -change ../../../libGeoIP/Libraries.osx64/libGeoIP.1.dylib @executable_path/../Frameworks/libGeoIP.1.dylib ../Spot-On-Kernel.app/Contents/MacOS/Spot-On-Kernel
libspoton_install.path  = .
libspoton_install.extra = cp ../../../libSpotOn/libspoton.dylib ../Spot-On-Kernel.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change /usr/local/lib/libgcrypt.11.dylib @loader_path/libgcrypt.11.dylib ../Spot-On-Kernel.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change ../../../libSpotOn/libspoton.dylib @executable_path/../Frameworks/libspoton.dylib ../Spot-On-Kernel.app/Contents/MacOS/Spot-On-Kernel
macdeployqt.path        = ../Spot-On-Kernel.app
macdeployqt.extra       = $$[QT_INSTALL_BINS]/macdeployqt ../Spot-On-Kernel.app -verbose=0
postinstall.path	= /Applications/Spot-On.d
postinstall.extra	= find /Applications/Spot-On.d -name .svn -exec rm -rf {} \\; 2>/dev/null; echo

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
INSTALLS	= macdeployqt \
                  libgeoip_data_install \
                  libgeoip_install \
                  libspoton_install \
                  spoton \
                  postinstall
