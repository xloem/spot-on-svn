cache()
libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\libSpotOn
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql widgets
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_LINKED_WITH_LIBGEOIP

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += Spot-On ..\\..\\libSpotOn\\libspoton.dll \
		   ..\\..\\libSpotOn\\*.o \
		   ..\\..\\libSpotOn\\test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -mtune=generic -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith
QMAKE_DISTCLEAN	+= .qmake.cache
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ..\\..\\. GUI ..\\..\\libSpotOn\\Include.win32 \
		   ..\\..\\libGeoIP\\Include.win32 \
		   ..\\..\\libOpenSsl\\Include.win32
LIBS		+= -L..\\..\\libSpotOn -L..\\..\\libSpotOn\\Libraries.win32 \
		   -L..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\libOpenSsl\\Libraries.win32 \
		   -lGeoIP-1 -leay32 -lgcrypt-11 -lpthread -lspoton -lssl32
PRE_TARGETDEPS = libspoton.dll

FORMS           = UI\\buzzpage.ui \
		  UI\\controlcenter.ui \
                  UI\\docviewer.ui \
                  UI\\logviewer.ui \
		  UI\\statusbar.ui

UI_HEADERS_DIR  = GUI

HEADERS		= GUI\\spot-on.h \
                  GUI\\spot-on-docviewer.h \
		  GUI\\spot-on-logviewer.h \
                  GUI\\spot-on-tabwidget.h \
		  GUI\\spot-on-textedit.h

SOURCES		= Common\\spot-on-crypt.cc \
		  Common\\spot-on-misc.cc \
                  Common\\spot-on-send.cc \
		  GUI\\spot-on-a.cc \
		  GUI\\spot-on-b.cc \
                  GUI\\spot-on-docviewer.cc \
		  GUI\\spot-on-logviewer.cc \
		  GUI\\spot-on-reencode.cc \
		  GUI\\spot-on-tabwidget.cc \
		  GUI\\spot-on-textedit.cc

TRANSLATIONS    = Translations\\spot-on_af.ts \
                  Translations\\spot-on_al.ts \
                  Translations\\spot-on_am.ts \
                  Translations\\spot-on_ar.ts \
                  Translations\\spot-on_as.ts \
                  Translations\\spot-on_az.ts \
                  Translations\\spot-on_be.ts \
                  Translations\\spot-on_bd.ts \
                  Translations\\spot-on_bg.ts \
                  Translations\\spot-on_ca.ts \
                  Translations\\spot-on_cr.ts \
                  Translations\\spot-on_cz.ts \
                  Translations\\spot-on_de.ts \
                  Translations\\spot-on_dk.ts \
                  Translations\\spot-on_ee.ts \
                  Translations\\spot-on_es.ts \
                  Translations\\spot-on_eo.ts \
                  Translations\\spot-on_et.ts \
                  Translations\\spot-on_eu.ts \
                  Translations\\spot-on_fi.ts \
                  Translations\\spot-on_fr.ts \
                  Translations\\spot-on_gl.ts \
                  Translations\\spot-on_gr.ts \
                  Translations\\spot-on_hb.ts \
                  Translations\\spot-on_hi.ts \
                  Translations\\spot-on_hr.ts \
                  Translations\\spot-on_hu.ts \
                  Translations\\spot-on_it.ts \
                  Translations\\spot-on_il.ts \
                  Translations\\spot-on_ie.ts \
                  Translations\\spot-on_id.ts \
                  Translations\\spot-on_ja.ts \
                  Translations\\spot-on_kk.ts \
                  Translations\\spot-on_kn.ts \
                  Translations\\spot-on_ko.ts \
                  Translations\\spot-on_ky.ts \
                  Translations\\spot-on_ku.ts \
                  Translations\\spot-on_lt.ts \
                  Translations\\spot-on_lk.ts \
                  Translations\\spot-on_lv.ts \
                  Translations\\spot-on_ml.ts \
                  Translations\\spot-on_mk.ts \
                  Translations\\spot-on_mn.ts \
                  Translations\\spot-on_ms.ts \
                  Translations\\spot-on_my.ts \
                  Translations\\spot-on_mr.ts \
                  Translations\\spot-on_mt.ts \
                  Translations\\spot-on_nl.ts \
                  Translations\\spot-on_no.ts \
                  Translations\\spot-on_np.ts \
                  Translations\\spot-on_pl.ts \
                  Translations\\spot-on_pa.ts \
                  Translations\\spot-on_pt.ts \
                  Translations\\spot-on_ps.ts \
                  Translations\\spot-on_ro.ts \
                  Translations\\spot-on_ru.ts \
                  Translations\\spot-on_rw.ts \
                  Translations\\spot-on_sv.ts \
                  Translations\\spot-on_sk.ts \
                  Translations\\spot-on_sl.ts \
                  Translations\\spot-on_sr.ts \
                  Translations\\spot-on_sq.ts \
                  Translations\\spot-on_sw.ts \
                  Translations\\spot-on_th.ts \
                  Translations\\spot-on_tr.ts \
                  Translations\\spot-on_vn.ts \
                  Translations\\spot-on_zh.ts \
                  Translations\\spot-on_zh_CN.ts \
                  Translations\\spot-on_zh_TW.ts \
                  Translations\\spot-on_zh_HK.ts

RESOURCES	= Icons\\icons.qrc \
                  Translations\\translations.qrc

RC_FILE		= Icons\\Resources\\spot-on.rc

TARGET		= Spot-On
PROJECTNAME	= Spot-On

geoip_data_install.path	= release\\GeoIP
geoip_data_install.files= ..\\..\\GeoIP-1.5.0\\data\\GeoIP.dat
icons.path		= release
icons.files		= Icons
libgeoip_install.path   = release
libgeoip_install.files  = ..\\..\\libGeoIP\\Libraries.win32\\libGeoIP-1.dll
libspoton_install.path  = release
libspoton_install.files = ..\\..\\libSpotOn\\libspoton.dll ..\\..\\libSpotOn\\Libraries.win32\\*.def ..\\..\\libSpotOn\\Libraries.win32\\*.dll
lrelease.extra          = $$[QT_INSTALL_BINS]\\lrelease spot-on-gui.win.pro
lrelease.path           = .
lupdate.extra           = $$[QT_INSTALL_BINS]\\lupdate spot-on-gui.win.pro
lupdate.path            = .
spoton.path		= release
spoton.files		= Spot-On.exe
translations.path 	= release\\Translations
translations.files	= Translations\\*.qm

INSTALLS	= geoip_data_install \
		  libgeoip_install \
                  libspoton_install \
                  icons \
                  lupdate \
                  lrelease \
		  spoton \
                  translations
