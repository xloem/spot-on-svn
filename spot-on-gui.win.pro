libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\LibSpotOn
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_MINIMUM_GCRYPT_VERSION=0x010500

# Unfortunately, the clean target assumes too much knowledge
# about the internals of LibSpotOn.

QMAKE_CLEAN     += Spot-On ..\\..\\LibSpotOn\\*.dll ..\\..\\LibSpotOn\\*.o \
		   ..\\..\\LibSpotOn\\test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -mtune=generic -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ..\\..\\. GUI ..\\..\\LibSpotOn\\Include.win32
LIBS		+= -L..\\..\\LibSpotOn -L..\\..\\LibSpotOn\\Libraries.win32 \
		   -lgcrypt-11 -lpthread -lspoton
PRE_TARGETDEPS = libspoton.dll

FORMS           = UI\\controlcenter.ui \
		  UI\\logviewer.ui

UI_HEADERS_DIR  = GUI

HEADERS		= GUI\\spot-on.h \
		  GUI\\spot-on-logviewer.h \
                  GUI\\spot-on-tabwidget.h \
		  GUI\\spot-on-textedit.h

SOURCES		= Common\\spot-on-gcrypt.cc \
		  Common\\spot-on-misc.cc \
                  Common\\spot-on-send.cc \
		  GUI\\spot-on.cc \
		  GUI\\spot-on-logviewer.cc \
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

RESOURCES	= Documentation\\documentation.qrc \
                  Icons\\icons.qrc \
                  Translations\\translations.qrc

TARGET		= Spot-On
PROJECTNAME	= Spot-On
