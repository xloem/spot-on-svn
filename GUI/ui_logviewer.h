/********************************************************************************
** Form generated from reading UI file 'logviewer.ui'
**
** Created: Wed 22. May 08:34:15 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LOGVIEWER_H
#define UI_LOGVIEWER_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHBoxLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QSpacerItem>
#include <QtGui/QStatusBar>
#include <QtGui/QTextBrowser>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_spoton_logviewer
{
public:
    QAction *action_Close;
    QAction *action_Empty_Log;
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QTextBrowser *log;
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer;
    QPushButton *clear;
    QMenuBar *menubar;
    QMenu *menu_File;
    QMenu *menu_Edit;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *spoton_logviewer)
    {
        if (spoton_logviewer->objectName().isEmpty())
            spoton_logviewer->setObjectName(QString::fromUtf8("spoton_logviewer"));
        spoton_logviewer->resize(800, 600);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/Logo/spoton-button-32.png"), QSize(), QIcon::Normal, QIcon::Off);
        spoton_logviewer->setWindowIcon(icon);
        action_Close = new QAction(spoton_logviewer);
        action_Close->setObjectName(QString::fromUtf8("action_Close"));
        action_Empty_Log = new QAction(spoton_logviewer);
        action_Empty_Log->setObjectName(QString::fromUtf8("action_Empty_Log"));
        centralwidget = new QWidget(spoton_logviewer);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        log = new QTextBrowser(centralwidget);
        log->setObjectName(QString::fromUtf8("log"));
        log->setTabChangesFocus(true);
        log->setAcceptRichText(false);
        log->setOpenLinks(false);

        verticalLayout->addWidget(log);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        clear = new QPushButton(centralwidget);
        clear->setObjectName(QString::fromUtf8("clear"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/clean.png"), QSize(), QIcon::Normal, QIcon::Off);
        clear->setIcon(icon1);

        horizontalLayout->addWidget(clear);


        verticalLayout->addLayout(horizontalLayout);

        spoton_logviewer->setCentralWidget(centralwidget);
        menubar = new QMenuBar(spoton_logviewer);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 800, 25));
        menu_File = new QMenu(menubar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        menu_Edit = new QMenu(menubar);
        menu_Edit->setObjectName(QString::fromUtf8("menu_Edit"));
        spoton_logviewer->setMenuBar(menubar);
        statusbar = new QStatusBar(spoton_logviewer);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        spoton_logviewer->setStatusBar(statusbar);
        QWidget::setTabOrder(log, clear);

        menubar->addAction(menu_File->menuAction());
        menubar->addAction(menu_Edit->menuAction());
        menu_File->addAction(action_Close);
        menu_Edit->addAction(action_Empty_Log);

        retranslateUi(spoton_logviewer);

        QMetaObject::connectSlotsByName(spoton_logviewer);
    } // setupUi

    void retranslateUi(QMainWindow *spoton_logviewer)
    {
        spoton_logviewer->setWindowTitle(QApplication::translate("spoton_logviewer", "Spot-On: Log Viewer", 0, QApplication::UnicodeUTF8));
        action_Close->setText(QApplication::translate("spoton_logviewer", "&Close", 0, QApplication::UnicodeUTF8));
        action_Empty_Log->setText(QApplication::translate("spoton_logviewer", "&Empty Log", 0, QApplication::UnicodeUTF8));
        clear->setText(QApplication::translate("spoton_logviewer", "Clear", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("spoton_logviewer", "&File", 0, QApplication::UnicodeUTF8));
        menu_Edit->setTitle(QApplication::translate("spoton_logviewer", "&Edit", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class spoton_logviewer: public Ui_spoton_logviewer {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LOGVIEWER_H
