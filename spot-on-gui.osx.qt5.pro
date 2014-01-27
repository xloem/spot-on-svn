cache()
libspoton.target = libspoton.dylib
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= core gui network sql widgets
CONFIG		+= app_bundle qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_LINKED_WITH_LIBGEOIP \
	   SPOTON_LINKED_WITH_LIBPTHREAD

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += Spot-On ../../libSpotOn/*.dylib ../../libSpotOn/*.o \
		   ../../libSpotOn/test
QMAKE_DISTCLEAN += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_DEBUG -= -O2
QMAKE_CXXFLAGS_DEBUG += -fPIE -fstack-protector-all -fwrapv \
			-mtune=generic -pie -Os \
			-Wall -Wcast-align -Wcast-qual \
                        -Werror -Wextra \
			-Woverloaded-virtual -Wpointer-arith \
			-Wstack-protector -Wstrict-overflow=4
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -mtune=generic -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
                          -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector -Wstrict-overflow=4
QMAKE_EXTRA_TARGETS = libspoton purge
QMAKE_LFLAGS_RELEASE =
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= . ../../. GUI ../../libGeoIP/Include.osx64 \
                   /usr/local/include \
                   /usr/local/ssl/include
ICON		= Icons/Logo/spoton-logo-transparent.icns
LIBS		+= -L/usr/local/lib -lgcrypt -lgpg-error \
		   -L../../libSpotOn -lspoton \
		   -L../../libGeoIP/Libraries.osx64 -lGeoIP \
                   -L/usr/local/ssl/lib -lcrypto -lssl \
                   -framework AppKit -framework Cocoa
PRE_TARGETDEPS = libspoton.dylib
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

FORMS           = UI/buzzpage.ui \
		  UI/chatwindow.ui \
		  UI/controlcenter.ui \
                  UI/logviewer.ui \
                  UI/passwordprompt.ui \
		  UI/rosetta.ui \
		  UI/statusbar.ui

UI_HEADERS_DIR  = GUI

HEADERS		= Common/spot-on-external-address.h \
		  GUI/spot-on.h \
		  GUI/spot-on-buzzpage.h \
		  GUI/spot-on-chatwindow.h \
		  GUI/spot-on-logviewer.h \
		  GUI/spot-on-rosetta.h \
		  GUI/spot-on-tabwidget.h \
		  GUI/spot-on-textedit.h

SOURCES		= Common/spot-on-crypt.cc \
		  Common/spot-on-external-address.cc \
		  Common/spot-on-misc.cc \
		  GUI/spot-on-a.cc \
		  GUI/spot-on-b.cc \
		  GUI/spot-on-c.cc \
		  GUI/spot-on-buzzpage.cc \
		  GUI/spot-on-chatwindow.cc \
		  GUI/spot-on-logviewer.cc \
		  GUI/spot-on-reencode.cc \
		  GUI/spot-on-rosetta.cc \
		  GUI/spot-on-tabwidget.cc \
		  GUI/spot-on-textedit.cc

OBJECTIVE_HEADERS += GUI/Cocoainitializer.h
OBJECTIVE_SOURCES += GUI/Cocoainitializer.mm

TRANSLATIONS    = Translations/spot-on_af.ts \
                  Translations/spot-on_al.ts \
                  Translations/spot-on_am.ts \
                  Translations/spot-on_ar.ts \
                  Translations/spot-on_as.ts \
                  Translations/spot-on_az.ts \
                  Translations/spot-on_be.ts \
                  Translations/spot-on_bd.ts \
                  Translations/spot-on_bg.ts \
                  Translations/spot-on_ca.ts \
                  Translations/spot-on_cr.ts \
                  Translations/spot-on_cz.ts \
                  Translations/spot-on_de.ts \
                  Translations/spot-on_dk.ts \
                  Translations/spot-on_ee.ts \
                  Translations/spot-on_es.ts \
                  Translations/spot-on_eo.ts \
                  Translations/spot-on_et.ts \
                  Translations/spot-on_eu.ts \
                  Translations/spot-on_fi.ts \
                  Translations/spot-on_fr.ts \
                  Translations/spot-on_gl.ts \
                  Translations/spot-on_gr.ts \
                  Translations/spot-on_hb.ts \
                  Translations/spot-on_hi.ts \
                  Translations/spot-on_hr.ts \
                  Translations/spot-on_hu.ts \
                  Translations/spot-on_it.ts \
                  Translations/spot-on_il.ts \
                  Translations/spot-on_ie.ts \
                  Translations/spot-on_id.ts \
                  Translations/spot-on_ja.ts \
                  Translations/spot-on_kk.ts \
                  Translations/spot-on_kn.ts \
                  Translations/spot-on_ko.ts \
                  Translations/spot-on_ky.ts \
                  Translations/spot-on_ku.ts \
                  Translations/spot-on_lt.ts \
                  Translations/spot-on_lk.ts \
                  Translations/spot-on_lv.ts \
                  Translations/spot-on_ml.ts \
                  Translations/spot-on_mk.ts \
                  Translations/spot-on_mn.ts \
                  Translations/spot-on_ms.ts \
                  Translations/spot-on_my.ts \
                  Translations/spot-on_mr.ts \
                  Translations/spot-on_mt.ts \
                  Translations/spot-on_nl.ts \
                  Translations/spot-on_no.ts \
                  Translations/spot-on_np.ts \
                  Translations/spot-on_pl.ts \
                  Translations/spot-on_pa.ts \
                  Translations/spot-on_pt.ts \
                  Translations/spot-on_ps.ts \
                  Translations/spot-on_ro.ts \
                  Translations/spot-on_ru.ts \
                  Translations/spot-on_rw.ts \
                  Translations/spot-on_sv.ts \
                  Translations/spot-on_sk.ts \
                  Translations/spot-on_sl.ts \
                  Translations/spot-on_sr.ts \
                  Translations/spot-on_sq.ts \
                  Translations/spot-on_sw.ts \
                  Translations/spot-on_th.ts \
                  Translations/spot-on_tr.ts \
                  Translations/spot-on_vn.ts \
                  Translations/spot-on_zh.ts \
                  Translations/spot-on_zh_TW.ts \
                  Translations/spot-on_zh_HK.ts

RESOURCES	= Icons/icons.qrc \
		  Sounds/sounds.qrc \
		  Translations/translations.qrc

TARGET		= Spot-On
PROJECTNAME	= Spot-On

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

spoton.path		= /Applications/Spot-On.d/Spot-On.app
spoton.files		= Spot-On.app/*
libgeoip_data_install.path = /Applications/Spot-On.d/GeoIP
libgeoip_data_install.files = ../../GeoIP-1.5.1/data/GeoIP.dat
libgeoip_install.path   = .
libgeoip_install.extra  = cp ../../libGeoIP/Libraries.osx64/libGeoIP.1.dylib ./Spot-On.app/Contents/Frameworks/libGeoIP.1.dylib && install_name_tool -change ../../libGeoIP/Libraries.osx64/libGeoIP.1.dylib @executable_path/../Frameworks/libGeoIP.1.dylib ./Spot-On.app/Contents/MacOS/Spot-On
libspoton_install.path  = .
libspoton_install.extra = cp ../../libSpotOn/libspoton.dylib ./Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change /usr/local/lib/libgcrypt.11.dylib @loader_path/libgcrypt.11.dylib ./Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change ../../libSpotOn/libspoton.dylib @executable_path/../Frameworks/libspoton.dylib ./Spot-On.app/Contents/MacOS/Spot-On
lrelease.extra          = $$[QT_INSTALL_BINS]/lrelease spot-on-gui.osx.pro
lrelease.path           = .
lupdate.extra           = $$[QT_INSTALL_BINS]/lupdate spot-on-gui.osx.pro
lupdate.path            = .
macdeployqt.path        = ./Spot-On.app
macdeployqt.extra       = $$[QT_INSTALL_BINS]/macdeployqt ./Spot-On.app -verbose=0
postinstall.path	= /Applications/Spot-On.d
postinstall.extra	= find /Applications/Spot-On.d -name .svn -exec rm -rf {} \\; 2>/dev/null; echo
translations.path 	= /Applications/Spot-On.d/Translations
translations.files	= Translations/*.qm

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
INSTALLS	= macdeployqt \
                  libgeoip_data_install \
                  libgeoip_install \
                  libspoton_install \
                  lupdate \
                  lrelease \
                  translations \
                  spoton \
                  postinstall
