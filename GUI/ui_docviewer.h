/********************************************************************************
** Form generated from reading UI file 'docviewer.ui'
**
** Created: Wed 22. May 08:34:15 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DOCVIEWER_H
#define UI_DOCVIEWER_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHBoxLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QStatusBar>
#include <QtGui/QWidget>
#include <QtWebKit/QWebView>

QT_BEGIN_NAMESPACE

class Ui_spoton_docviewer
{
public:
    QAction *action_Close;
    QAction *action_Empty_Log;
    QWidget *centralwidget;
    QHBoxLayout *horizontalLayout;
    QWebView *htmlView;
    QMenuBar *menubar;
    QMenu *menu_File;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *spoton_docviewer)
    {
        if (spoton_docviewer->objectName().isEmpty())
            spoton_docviewer->setObjectName(QString::fromUtf8("spoton_docviewer"));
        spoton_docviewer->resize(800, 600);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/Logo/spoton-button-32.png"), QSize(), QIcon::Normal, QIcon::Off);
        spoton_docviewer->setWindowIcon(icon);
        action_Close = new QAction(spoton_docviewer);
        action_Close->setObjectName(QString::fromUtf8("action_Close"));
        action_Empty_Log = new QAction(spoton_docviewer);
        action_Empty_Log->setObjectName(QString::fromUtf8("action_Empty_Log"));
        centralwidget = new QWidget(spoton_docviewer);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        horizontalLayout = new QHBoxLayout(centralwidget);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        htmlView = new QWebView(centralwidget);
        htmlView->setObjectName(QString::fromUtf8("htmlView"));
        htmlView->setUrl(QUrl(QString::fromUtf8("qrc:/README.html")));
        htmlView->setRenderHints(QPainter::Antialiasing|QPainter::HighQualityAntialiasing|QPainter::SmoothPixmapTransform|QPainter::TextAntialiasing);

        horizontalLayout->addWidget(htmlView);

        spoton_docviewer->setCentralWidget(centralwidget);
        menubar = new QMenuBar(spoton_docviewer);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 800, 25));
        menu_File = new QMenu(menubar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        spoton_docviewer->setMenuBar(menubar);
        statusbar = new QStatusBar(spoton_docviewer);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        spoton_docviewer->setStatusBar(statusbar);

        menubar->addAction(menu_File->menuAction());
        menu_File->addAction(action_Close);

        retranslateUi(spoton_docviewer);

        QMetaObject::connectSlotsByName(spoton_docviewer);
    } // setupUi

    void retranslateUi(QMainWindow *spoton_docviewer)
    {
        spoton_docviewer->setWindowTitle(QApplication::translate("spoton_docviewer", "Spot-On: Documentation Viewer", 0, QApplication::UnicodeUTF8));
        action_Close->setText(QApplication::translate("spoton_docviewer", "&Close", 0, QApplication::UnicodeUTF8));
        action_Empty_Log->setText(QApplication::translate("spoton_docviewer", "&Empty Log", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("spoton_docviewer", "&File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class spoton_docviewer: public Ui_spoton_docviewer {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DOCVIEWER_H
