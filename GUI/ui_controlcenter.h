/********************************************************************************
** Form generated from reading UI file 'controlcenter.ui'
**
** Created: Wed 22. May 14:48:45 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CONTROLCENTER_H
#define UI_CONTROLCENTER_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QComboBox>
#include <QtGui/QGridLayout>
#include <QtGui/QGroupBox>
#include <QtGui/QHBoxLayout>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QPushButton>
#include <QtGui/QRadioButton>
#include <QtGui/QScrollArea>
#include <QtGui/QSpacerItem>
#include <QtGui/QSpinBox>
#include <QtGui/QSplitter>
#include <QtGui/QStatusBar>
#include <QtGui/QTabWidget>
#include <QtGui/QTableWidget>
#include <QtGui/QTextBrowser>
#include <QtGui/QTextEdit>
#include <QtGui/QToolButton>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>
#include "GUI/spot-on-tabwidget.h"
#include "GUI/spot-on-textedit.h"

QT_BEGIN_NAMESPACE

class Ui_spoton_mainwindow
{
public:
    QAction *action_Quit;
    QAction *action_Log_Viewer;
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout_3;
    spoton_tabwidget *tab;
    QWidget *tab_chat;
    QVBoxLayout *verticalLayout_18;
    QWidget *layouttab;
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBox_9;
    QVBoxLayout *verticalLayout_7;
    QTextBrowser *messages;
    spoton_textedit *message;
    QHBoxLayout *horizontalLayout;
    QComboBox *status;
    QPushButton *sendMessage;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_19;
    QTableWidget *participants;
    QWidget *tab_neighbors;
    QVBoxLayout *verticalLayout_8;
    QVBoxLayout *verticalLayout_2;
    QGroupBox *groupBox_addkey_2;
    QVBoxLayout *verticalLayout_22;
    QToolButton *toolButtonCopytoClipboard;
    QHBoxLayout *horizontalLayout_30;
    QRadioButton *addFriendPublicKeyRadio;
    QRadioButton *addFriendSymmetricBundleRadio;
    QTextEdit *friendInformation;
    QHBoxLayout *horizontalLayout_21;
    QSpacerItem *horizontalSpacer_8;
    QPushButton *addFriend;
    QPushButton *clearFriend;
    QSpacerItem *horizontalSpacer_20;
    QWidget *tab_email;
    QVBoxLayout *verticalLayout_29;
    QTabWidget *mailTab;
    QWidget *tab_4;
    QVBoxLayout *verticalLayout_26;
    QHBoxLayout *horizontalLayout_38;
    QComboBox *folder;
    QPushButton *retrieveMail;
    QPushButton *refreshMail;
    QSpacerItem *horizontalSpacer_32;
    QPushButton *deleteMail;
    QPushButton *emptyTrash;
    QSplitter *readVerticalSplitter;
    QTableWidget *mail;
    QWidget *layoutWidget_2;
    QGridLayout *gridLayout_2;
    QLineEdit *mailFrom;
    QLabel *label_from;
    QLabel *label_30;
    QLineEdit *mailSubject;
    QTextBrowser *mailMessage;
    QLabel *label_29;
    QWidget *tab_5;
    QVBoxLayout *verticalLayout_27;
    QHBoxLayout *horizontalLayout_29;
    QSpacerItem *horizontalSpacer_27;
    QPushButton *sendMail;
    QPushButton *pushButtonClearOutgoingMessage;
    QGridLayout *gridLayout_4;
    QLabel *label_10;
    QHBoxLayout *horizontalLayout_33;
    QComboBox *participantsCombo;
    QSpacerItem *horizontalSpacer_28;
    QLabel *label_25;
    QLineEdit *outgoingSubject;
    QLabel *label_26;
    QTextEdit *outgoingMessage;
    QHBoxLayout *horizontalLayout_31;
    QLineEdit *goldbug;
    QPushButton *generateGoldBug;
    QSpacerItem *horizontalSpacer_33;
    QLabel *label_6;
    QWidget *tab_settings;
    QVBoxLayout *verticalLayout_15;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QHBoxLayout *horizontalLayout_26;
    QVBoxLayout *verticalLayout_4;
    QGroupBox *kernelBox;
    QVBoxLayout *verticalLayout_12;
    QHBoxLayout *horizontalLayout_14;
    QPushButton *activateKernel;
    QLabel *label_17;
    QLineEdit *pid;
    QPushButton *deactivateKernel;
    QHBoxLayout *horizontalLayout_15;
    QLabel *label_18;
    QLineEdit *kernelPath;
    QPushButton *selectKernelPath;
    QGroupBox *nodeName_2;
    QVBoxLayout *verticalLayout_11;
    QHBoxLayout *horizontalLayout_6;
    QLineEdit *nodeName;
    QPushButton *saveNodeName;
    QGroupBox *groupBox_2;
    QVBoxLayout *verticalLayout_10;
    QHBoxLayout *horizontalLayout_9;
    QRadioButton *ipv4Neighbor;
    QRadioButton *ipv6Neighbor;
    QHBoxLayout *horizontalLayout_10;
    QLineEdit *neighborIP;
    QSpinBox *neighborPort;
    QHBoxLayout *horizontalLayout_11;
    QPushButton *addNeighbor;
    QLineEdit *neighborScopeId;
    QGroupBox *listenersBox;
    QVBoxLayout *verticalLayout_6;
    QHBoxLayout *horizontalLayout_12;
    QRadioButton *ipv4Listener;
    QRadioButton *ipv6Listener;
    QComboBox *listenerIPCombo;
    QHBoxLayout *horizontalLayout_16;
    QLabel *label_11;
    QLineEdit *listenerIP;
    QHBoxLayout *horizontalLayout_17;
    QLabel *listenerScopeIdLabel;
    QLineEdit *listenerScopeId;
    QHBoxLayout *horizontalLayout_18;
    QLabel *label_12;
    QSpinBox *listenerPort;
    QPushButton *addListener;
    QGroupBox *passphraseGroupBox;
    QVBoxLayout *verticalLayout_9;
    QHBoxLayout *horizontalLayout_8;
    QLabel *label_16;
    QSpinBox *saltLength;
    QHBoxLayout *horizontalLayout_7;
    QLabel *label_23;
    QComboBox *rsaKeySize;
    QHBoxLayout *horizontalLayout_5;
    QLabel *label_15;
    QSpinBox *iterationCount;
    QHBoxLayout *horizontalLayout_4;
    QLabel *label_14;
    QComboBox *hashType;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label;
    QComboBox *cipherType;
    QGridLayout *gridLayout;
    QLabel *label_55;
    QLabel *label_58;
    QLineEdit *passphrase1;
    QLabel *label_56;
    QLineEdit *passphrase2;
    QPushButton *setPassphrase;
    QWidget *tab_login;
    QHBoxLayout *horizontalLayout_34;
    QVBoxLayout *verticalLayout_5;
    QSpacerItem *verticalSpacer_5;
    QHBoxLayout *horizontalLayout_32;
    QSpacerItem *horizontalSpacer_35;
    QLabel *label_31;
    QSpacerItem *horizontalSpacer_34;
    QHBoxLayout *horizontalLayout_13;
    QSpacerItem *horizontalSpacer_6;
    QLabel *passphraseLabel;
    QLineEdit *passphrase;
    QPushButton *passphraseButton;
    QSpacerItem *horizontalSpacer_9;
    QSpacerItem *verticalSpacer_7;
    QHBoxLayout *horizontalLayout_3;
    QSpacerItem *horizontalSpacer;
    QLabel *label_4;
    QSpacerItem *horizontalSpacer_2;
    QSpacerItem *verticalSpacer_2;
    QStatusBar *statusbar;
    QMenuBar *menubar;
    QMenu *menu_File;

    void setupUi(QMainWindow *spoton_mainwindow)
    {
        if (spoton_mainwindow->objectName().isEmpty())
            spoton_mainwindow->setObjectName(QString::fromUtf8("spoton_mainwindow"));
        spoton_mainwindow->resize(624, 901);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/Logo/spoton-button-32.png"), QSize(), QIcon::Normal, QIcon::Off);
        spoton_mainwindow->setWindowIcon(icon);
        action_Quit = new QAction(spoton_mainwindow);
        action_Quit->setObjectName(QString::fromUtf8("action_Quit"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/quit.png"), QSize(), QIcon::Normal, QIcon::Off);
        action_Quit->setIcon(icon1);
        action_Log_Viewer = new QAction(spoton_mainwindow);
        action_Log_Viewer->setObjectName(QString::fromUtf8("action_Log_Viewer"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/logview.png"), QSize(), QIcon::Normal, QIcon::Off);
        action_Log_Viewer->setIcon(icon2);
        centralwidget = new QWidget(spoton_mainwindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        verticalLayout_3 = new QVBoxLayout(centralwidget);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        verticalLayout_3->setContentsMargins(-1, -1, -1, 0);
        tab = new spoton_tabwidget(centralwidget);
        tab->setObjectName(QString::fromUtf8("tab"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(tab->sizePolicy().hasHeightForWidth());
        tab->setSizePolicy(sizePolicy);
        tab->setTabPosition(QTabWidget::East);
        tab->setIconSize(QSize(32, 32));
        tab->setMovable(false);
        tab_chat = new QWidget();
        tab_chat->setObjectName(QString::fromUtf8("tab_chat"));
        verticalLayout_18 = new QVBoxLayout(tab_chat);
        verticalLayout_18->setContentsMargins(0, 0, 0, 0);
        verticalLayout_18->setObjectName(QString::fromUtf8("verticalLayout_18"));
        layouttab = new QWidget(tab_chat);
        layouttab->setObjectName(QString::fromUtf8("layouttab"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(layouttab->sizePolicy().hasHeightForWidth());
        layouttab->setSizePolicy(sizePolicy1);
        verticalLayout = new QVBoxLayout(layouttab);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        groupBox_9 = new QGroupBox(layouttab);
        groupBox_9->setObjectName(QString::fromUtf8("groupBox_9"));
        verticalLayout_7 = new QVBoxLayout(groupBox_9);
        verticalLayout_7->setObjectName(QString::fromUtf8("verticalLayout_7"));
        messages = new QTextBrowser(groupBox_9);
        messages->setObjectName(QString::fromUtf8("messages"));
        messages->setTabChangesFocus(true);

        verticalLayout_7->addWidget(messages);

        message = new spoton_textedit(groupBox_9);
        message->setObjectName(QString::fromUtf8("message"));
        QSizePolicy sizePolicy2(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(message->sizePolicy().hasHeightForWidth());
        message->setSizePolicy(sizePolicy2);
        message->setTabChangesFocus(true);
        message->setAcceptRichText(false);

        verticalLayout_7->addWidget(message);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        status = new QComboBox(groupBox_9);
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/Status/status_blue.png"), QSize(), QIcon::Normal, QIcon::Off);
        status->addItem(icon3, QString());
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/Status/status_red.png"), QSize(), QIcon::Normal, QIcon::Off);
        status->addItem(icon4, QString());
        QIcon icon5;
        icon5.addFile(QString::fromUtf8(":/Status/status_gray.png"), QSize(), QIcon::Normal, QIcon::Off);
        status->addItem(icon5, QString());
        QIcon icon6;
        icon6.addFile(QString::fromUtf8(":/Status/status_lightgreen.png"), QSize(), QIcon::Normal, QIcon::Off);
        status->addItem(icon6, QString());
        status->setObjectName(QString::fromUtf8("status"));
        QSizePolicy sizePolicy3(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy3.setHorizontalStretch(0);
        sizePolicy3.setVerticalStretch(0);
        sizePolicy3.setHeightForWidth(status->sizePolicy().hasHeightForWidth());
        status->setSizePolicy(sizePolicy3);
        status->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        horizontalLayout->addWidget(status);

        sendMessage = new QPushButton(groupBox_9);
        sendMessage->setObjectName(QString::fromUtf8("sendMessage"));
        QIcon icon7;
        icon7.addFile(QString::fromUtf8(":/ok.png"), QSize(), QIcon::Normal, QIcon::Off);
        sendMessage->setIcon(icon7);

        horizontalLayout->addWidget(sendMessage);


        verticalLayout_7->addLayout(horizontalLayout);


        verticalLayout->addWidget(groupBox_9);

        groupBox = new QGroupBox(layouttab);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        verticalLayout_19 = new QVBoxLayout(groupBox);
        verticalLayout_19->setObjectName(QString::fromUtf8("verticalLayout_19"));
        participants = new QTableWidget(groupBox);
        if (participants->columnCount() < 6)
            participants->setColumnCount(6);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        participants->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        participants->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
        participants->setHorizontalHeaderItem(2, __qtablewidgetitem2);
        QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
        participants->setHorizontalHeaderItem(3, __qtablewidgetitem3);
        QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
        participants->setHorizontalHeaderItem(4, __qtablewidgetitem4);
        QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
        participants->setHorizontalHeaderItem(5, __qtablewidgetitem5);
        participants->setObjectName(QString::fromUtf8("participants"));
        participants->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
        participants->setSelectionBehavior(QAbstractItemView::SelectRows);
        participants->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        participants->setSortingEnabled(true);
        participants->horizontalHeader()->setDefaultSectionSize(150);
        participants->horizontalHeader()->setStretchLastSection(true);

        verticalLayout_19->addWidget(participants);


        verticalLayout->addWidget(groupBox);


        verticalLayout_18->addWidget(layouttab);

        QIcon icon8;
        icon8.addFile(QString::fromUtf8(":/tab-chat.png"), QSize(), QIcon::Normal, QIcon::Off);
        tab->addTab(tab_chat, icon8, QString());
        tab_neighbors = new QWidget();
        tab_neighbors->setObjectName(QString::fromUtf8("tab_neighbors"));
        verticalLayout_8 = new QVBoxLayout(tab_neighbors);
        verticalLayout_8->setObjectName(QString::fromUtf8("verticalLayout_8"));
        verticalLayout_2 = new QVBoxLayout();
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        groupBox_addkey_2 = new QGroupBox(tab_neighbors);
        groupBox_addkey_2->setObjectName(QString::fromUtf8("groupBox_addkey_2"));
        verticalLayout_22 = new QVBoxLayout(groupBox_addkey_2);
        verticalLayout_22->setObjectName(QString::fromUtf8("verticalLayout_22"));
        toolButtonCopytoClipboard = new QToolButton(groupBox_addkey_2);
        toolButtonCopytoClipboard->setObjectName(QString::fromUtf8("toolButtonCopytoClipboard"));
        QIcon icon9;
        icon9.addFile(QString::fromUtf8(":/addkey.png"), QSize(), QIcon::Normal, QIcon::Off);
        toolButtonCopytoClipboard->setIcon(icon9);
        toolButtonCopytoClipboard->setPopupMode(QToolButton::InstantPopup);
        toolButtonCopytoClipboard->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

        verticalLayout_22->addWidget(toolButtonCopytoClipboard);

        horizontalLayout_30 = new QHBoxLayout();
        horizontalLayout_30->setObjectName(QString::fromUtf8("horizontalLayout_30"));
        addFriendPublicKeyRadio = new QRadioButton(groupBox_addkey_2);
        addFriendPublicKeyRadio->setObjectName(QString::fromUtf8("addFriendPublicKeyRadio"));
        addFriendPublicKeyRadio->setIcon(icon9);
        addFriendPublicKeyRadio->setChecked(true);

        horizontalLayout_30->addWidget(addFriendPublicKeyRadio);

        addFriendSymmetricBundleRadio = new QRadioButton(groupBox_addkey_2);
        addFriendSymmetricBundleRadio->setObjectName(QString::fromUtf8("addFriendSymmetricBundleRadio"));
        QIcon icon10;
        icon10.addFile(QString::fromUtf8(":/repleo.png"), QSize(), QIcon::Normal, QIcon::Off);
        addFriendSymmetricBundleRadio->setIcon(icon10);

        horizontalLayout_30->addWidget(addFriendSymmetricBundleRadio);


        verticalLayout_22->addLayout(horizontalLayout_30);

        friendInformation = new QTextEdit(groupBox_addkey_2);
        friendInformation->setObjectName(QString::fromUtf8("friendInformation"));
        friendInformation->setTabChangesFocus(true);

        verticalLayout_22->addWidget(friendInformation);

        horizontalLayout_21 = new QHBoxLayout();
        horizontalLayout_21->setObjectName(QString::fromUtf8("horizontalLayout_21"));
        horizontalSpacer_8 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_21->addItem(horizontalSpacer_8);

        addFriend = new QPushButton(groupBox_addkey_2);
        addFriend->setObjectName(QString::fromUtf8("addFriend"));
        QIcon icon11;
        icon11.addFile(QString::fromUtf8(":/add.png"), QSize(), QIcon::Normal, QIcon::Off);
        addFriend->setIcon(icon11);

        horizontalLayout_21->addWidget(addFriend);

        clearFriend = new QPushButton(groupBox_addkey_2);
        clearFriend->setObjectName(QString::fromUtf8("clearFriend"));
        QIcon icon12;
        icon12.addFile(QString::fromUtf8(":/clean.png"), QSize(), QIcon::Normal, QIcon::Off);
        clearFriend->setIcon(icon12);

        horizontalLayout_21->addWidget(clearFriend);

        horizontalSpacer_20 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_21->addItem(horizontalSpacer_20);


        verticalLayout_22->addLayout(horizontalLayout_21);


        verticalLayout_2->addWidget(groupBox_addkey_2);


        verticalLayout_8->addLayout(verticalLayout_2);

        QIcon icon13;
        icon13.addFile(QString::fromUtf8(":/tab-neighbours.png"), QSize(), QIcon::Normal, QIcon::Off);
        tab->addTab(tab_neighbors, icon13, QString());
        tab_email = new QWidget();
        tab_email->setObjectName(QString::fromUtf8("tab_email"));
        verticalLayout_29 = new QVBoxLayout(tab_email);
        verticalLayout_29->setObjectName(QString::fromUtf8("verticalLayout_29"));
        mailTab = new QTabWidget(tab_email);
        mailTab->setObjectName(QString::fromUtf8("mailTab"));
        mailTab->setTabPosition(QTabWidget::South);
        tab_4 = new QWidget();
        tab_4->setObjectName(QString::fromUtf8("tab_4"));
        verticalLayout_26 = new QVBoxLayout(tab_4);
        verticalLayout_26->setObjectName(QString::fromUtf8("verticalLayout_26"));
        horizontalLayout_38 = new QHBoxLayout();
        horizontalLayout_38->setObjectName(QString::fromUtf8("horizontalLayout_38"));
        folder = new QComboBox(tab_4);
        QIcon icon14;
        icon14.addFile(QString::fromUtf8(":/email-inbox.png"), QSize(), QIcon::Normal, QIcon::Off);
        folder->addItem(icon14, QString());
        QIcon icon15;
        icon15.addFile(QString::fromUtf8(":/email-sent.png"), QSize(), QIcon::Normal, QIcon::Off);
        folder->addItem(icon15, QString());
        QIcon icon16;
        icon16.addFile(QString::fromUtf8(":/email-trash.png"), QSize(), QIcon::Normal, QIcon::Off);
        folder->addItem(icon16, QString());
        folder->setObjectName(QString::fromUtf8("folder"));
        folder->setIconSize(QSize(20, 21));

        horizontalLayout_38->addWidget(folder);

        retrieveMail = new QPushButton(tab_4);
        retrieveMail->setObjectName(QString::fromUtf8("retrieveMail"));
        QIcon icon17;
        icon17.addFile(QString::fromUtf8(":/down.png"), QSize(), QIcon::Normal, QIcon::Off);
        retrieveMail->setIcon(icon17);

        horizontalLayout_38->addWidget(retrieveMail);

        refreshMail = new QPushButton(tab_4);
        refreshMail->setObjectName(QString::fromUtf8("refreshMail"));
        QIcon icon18;
        icon18.addFile(QString::fromUtf8(":/reload.png"), QSize(), QIcon::Normal, QIcon::Off);
        refreshMail->setIcon(icon18);

        horizontalLayout_38->addWidget(refreshMail);

        horizontalSpacer_32 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_38->addItem(horizontalSpacer_32);

        deleteMail = new QPushButton(tab_4);
        deleteMail->setObjectName(QString::fromUtf8("deleteMail"));
        QIcon icon19;
        icon19.addFile(QString::fromUtf8(":/delete.png"), QSize(), QIcon::Normal, QIcon::Off);
        deleteMail->setIcon(icon19);

        horizontalLayout_38->addWidget(deleteMail);

        emptyTrash = new QPushButton(tab_4);
        emptyTrash->setObjectName(QString::fromUtf8("emptyTrash"));
        emptyTrash->setIcon(icon12);

        horizontalLayout_38->addWidget(emptyTrash);


        verticalLayout_26->addLayout(horizontalLayout_38);

        readVerticalSplitter = new QSplitter(tab_4);
        readVerticalSplitter->setObjectName(QString::fromUtf8("readVerticalSplitter"));
        readVerticalSplitter->setOrientation(Qt::Vertical);
        readVerticalSplitter->setChildrenCollapsible(false);
        mail = new QTableWidget(readVerticalSplitter);
        if (mail->columnCount() < 6)
            mail->setColumnCount(6);
        QTableWidgetItem *__qtablewidgetitem6 = new QTableWidgetItem();
        mail->setHorizontalHeaderItem(0, __qtablewidgetitem6);
        QTableWidgetItem *__qtablewidgetitem7 = new QTableWidgetItem();
        mail->setHorizontalHeaderItem(1, __qtablewidgetitem7);
        QTableWidgetItem *__qtablewidgetitem8 = new QTableWidgetItem();
        mail->setHorizontalHeaderItem(2, __qtablewidgetitem8);
        QTableWidgetItem *__qtablewidgetitem9 = new QTableWidgetItem();
        mail->setHorizontalHeaderItem(3, __qtablewidgetitem9);
        QTableWidgetItem *__qtablewidgetitem10 = new QTableWidgetItem();
        mail->setHorizontalHeaderItem(4, __qtablewidgetitem10);
        QTableWidgetItem *__qtablewidgetitem11 = new QTableWidgetItem();
        mail->setHorizontalHeaderItem(5, __qtablewidgetitem11);
        mail->setObjectName(QString::fromUtf8("mail"));
        mail->setSelectionBehavior(QAbstractItemView::SelectRows);
        mail->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        mail->setSortingEnabled(true);
        readVerticalSplitter->addWidget(mail);
        mail->horizontalHeader()->setDefaultSectionSize(150);
        mail->horizontalHeader()->setStretchLastSection(true);
        layoutWidget_2 = new QWidget(readVerticalSplitter);
        layoutWidget_2->setObjectName(QString::fromUtf8("layoutWidget_2"));
        gridLayout_2 = new QGridLayout(layoutWidget_2);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        gridLayout_2->setContentsMargins(0, 12, 0, 0);
        mailFrom = new QLineEdit(layoutWidget_2);
        mailFrom->setObjectName(QString::fromUtf8("mailFrom"));
        mailFrom->setReadOnly(true);

        gridLayout_2->addWidget(mailFrom, 0, 2, 1, 1);

        label_from = new QLabel(layoutWidget_2);
        label_from->setObjectName(QString::fromUtf8("label_from"));

        gridLayout_2->addWidget(label_from, 0, 0, 1, 1);

        label_30 = new QLabel(layoutWidget_2);
        label_30->setObjectName(QString::fromUtf8("label_30"));
        QSizePolicy sizePolicy4(QSizePolicy::Fixed, QSizePolicy::Preferred);
        sizePolicy4.setHorizontalStretch(0);
        sizePolicy4.setVerticalStretch(0);
        sizePolicy4.setHeightForWidth(label_30->sizePolicy().hasHeightForWidth());
        label_30->setSizePolicy(sizePolicy4);
        label_30->setMinimumSize(QSize(75, 0));

        gridLayout_2->addWidget(label_30, 2, 0, 1, 1);

        mailSubject = new QLineEdit(layoutWidget_2);
        mailSubject->setObjectName(QString::fromUtf8("mailSubject"));
        mailSubject->setReadOnly(true);

        gridLayout_2->addWidget(mailSubject, 1, 2, 1, 1);

        mailMessage = new QTextBrowser(layoutWidget_2);
        mailMessage->setObjectName(QString::fromUtf8("mailMessage"));
        mailMessage->setTabChangesFocus(true);

        gridLayout_2->addWidget(mailMessage, 2, 2, 1, 1);

        label_29 = new QLabel(layoutWidget_2);
        label_29->setObjectName(QString::fromUtf8("label_29"));
        sizePolicy4.setHeightForWidth(label_29->sizePolicy().hasHeightForWidth());
        label_29->setSizePolicy(sizePolicy4);
        label_29->setMinimumSize(QSize(75, 32));

        gridLayout_2->addWidget(label_29, 1, 0, 1, 1);

        readVerticalSplitter->addWidget(layoutWidget_2);

        verticalLayout_26->addWidget(readVerticalSplitter);

        QIcon icon20;
        icon20.addFile(QString::fromUtf8(":/tab-email.png"), QSize(), QIcon::Normal, QIcon::Off);
        mailTab->addTab(tab_4, icon20, QString());
        tab_5 = new QWidget();
        tab_5->setObjectName(QString::fromUtf8("tab_5"));
        verticalLayout_27 = new QVBoxLayout(tab_5);
        verticalLayout_27->setObjectName(QString::fromUtf8("verticalLayout_27"));
        horizontalLayout_29 = new QHBoxLayout();
        horizontalLayout_29->setObjectName(QString::fromUtf8("horizontalLayout_29"));
        horizontalSpacer_27 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_29->addItem(horizontalSpacer_27);

        sendMail = new QPushButton(tab_5);
        sendMail->setObjectName(QString::fromUtf8("sendMail"));
        sendMail->setIcon(icon20);

        horizontalLayout_29->addWidget(sendMail);

        pushButtonClearOutgoingMessage = new QPushButton(tab_5);
        pushButtonClearOutgoingMessage->setObjectName(QString::fromUtf8("pushButtonClearOutgoingMessage"));
        pushButtonClearOutgoingMessage->setIcon(icon12);

        horizontalLayout_29->addWidget(pushButtonClearOutgoingMessage);


        verticalLayout_27->addLayout(horizontalLayout_29);

        gridLayout_4 = new QGridLayout();
        gridLayout_4->setObjectName(QString::fromUtf8("gridLayout_4"));
        label_10 = new QLabel(tab_5);
        label_10->setObjectName(QString::fromUtf8("label_10"));
        sizePolicy4.setHeightForWidth(label_10->sizePolicy().hasHeightForWidth());
        label_10->setSizePolicy(sizePolicy4);
        label_10->setMinimumSize(QSize(75, 0));

        gridLayout_4->addWidget(label_10, 1, 0, 1, 1);

        horizontalLayout_33 = new QHBoxLayout();
        horizontalLayout_33->setObjectName(QString::fromUtf8("horizontalLayout_33"));
        participantsCombo = new QComboBox(tab_5);
        QIcon icon21;
        icon21.addFile(QString::fromUtf8(":/plist_confirmed_as_permanent_friend.png"), QSize(), QIcon::Normal, QIcon::Off);
        participantsCombo->addItem(icon21, QString());
        participantsCombo->setObjectName(QString::fromUtf8("participantsCombo"));

        horizontalLayout_33->addWidget(participantsCombo);

        horizontalSpacer_28 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_33->addItem(horizontalSpacer_28);


        gridLayout_4->addLayout(horizontalLayout_33, 1, 1, 1, 1);

        label_25 = new QLabel(tab_5);
        label_25->setObjectName(QString::fromUtf8("label_25"));
        sizePolicy4.setHeightForWidth(label_25->sizePolicy().hasHeightForWidth());
        label_25->setSizePolicy(sizePolicy4);
        label_25->setMinimumSize(QSize(75, 32));

        gridLayout_4->addWidget(label_25, 2, 0, 1, 1);

        outgoingSubject = new QLineEdit(tab_5);
        outgoingSubject->setObjectName(QString::fromUtf8("outgoingSubject"));

        gridLayout_4->addWidget(outgoingSubject, 2, 1, 1, 1);

        label_26 = new QLabel(tab_5);
        label_26->setObjectName(QString::fromUtf8("label_26"));
        sizePolicy4.setHeightForWidth(label_26->sizePolicy().hasHeightForWidth());
        label_26->setSizePolicy(sizePolicy4);
        label_26->setMinimumSize(QSize(75, 0));

        gridLayout_4->addWidget(label_26, 3, 0, 1, 1);

        outgoingMessage = new QTextEdit(tab_5);
        outgoingMessage->setObjectName(QString::fromUtf8("outgoingMessage"));
        outgoingMessage->setStyleSheet(QString::fromUtf8("background-color: qlineargradient(spread:pad, x1:0.968, y1:0.932, x2:0.513, y2:0.5, stop:0 rgba(183, 235, 255, 255), stop:1 rgba(255, 255, 255, 255));"));
        outgoingMessage->setTabChangesFocus(true);

        gridLayout_4->addWidget(outgoingMessage, 3, 1, 1, 1);

        horizontalLayout_31 = new QHBoxLayout();
        horizontalLayout_31->setObjectName(QString::fromUtf8("horizontalLayout_31"));
        goldbug = new QLineEdit(tab_5);
        goldbug->setObjectName(QString::fromUtf8("goldbug"));

        horizontalLayout_31->addWidget(goldbug);

        generateGoldBug = new QPushButton(tab_5);
        generateGoldBug->setObjectName(QString::fromUtf8("generateGoldBug"));
        QIcon icon22;
        icon22.addFile(QString::fromUtf8(":/goldbug.png"), QSize(), QIcon::Normal, QIcon::Off);
        generateGoldBug->setIcon(icon22);

        horizontalLayout_31->addWidget(generateGoldBug);

        horizontalSpacer_33 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_31->addItem(horizontalSpacer_33);


        gridLayout_4->addLayout(horizontalLayout_31, 4, 1, 1, 1);

        label_6 = new QLabel(tab_5);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        gridLayout_4->addWidget(label_6, 4, 0, 1, 1);


        verticalLayout_27->addLayout(gridLayout_4);

        QIcon icon23;
        icon23.addFile(QString::fromUtf8(":/modify.png"), QSize(), QIcon::Normal, QIcon::Off);
        mailTab->addTab(tab_5, icon23, QString());

        verticalLayout_29->addWidget(mailTab);

        tab->addTab(tab_email, icon20, QString());
        tab_settings = new QWidget();
        tab_settings->setObjectName(QString::fromUtf8("tab_settings"));
        verticalLayout_15 = new QVBoxLayout(tab_settings);
        verticalLayout_15->setContentsMargins(0, 0, 0, 0);
        verticalLayout_15->setObjectName(QString::fromUtf8("verticalLayout_15"));
        scrollArea = new QScrollArea(tab_settings);
        scrollArea->setObjectName(QString::fromUtf8("scrollArea"));
        sizePolicy2.setHeightForWidth(scrollArea->sizePolicy().hasHeightForWidth());
        scrollArea->setSizePolicy(sizePolicy2);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName(QString::fromUtf8("scrollAreaWidgetContents"));
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 559, 833));
        horizontalLayout_26 = new QHBoxLayout(scrollAreaWidgetContents);
        horizontalLayout_26->setObjectName(QString::fromUtf8("horizontalLayout_26"));
        verticalLayout_4 = new QVBoxLayout();
        verticalLayout_4->setObjectName(QString::fromUtf8("verticalLayout_4"));
        kernelBox = new QGroupBox(scrollAreaWidgetContents);
        kernelBox->setObjectName(QString::fromUtf8("kernelBox"));
        verticalLayout_12 = new QVBoxLayout(kernelBox);
        verticalLayout_12->setObjectName(QString::fromUtf8("verticalLayout_12"));
        horizontalLayout_14 = new QHBoxLayout();
        horizontalLayout_14->setObjectName(QString::fromUtf8("horizontalLayout_14"));
        activateKernel = new QPushButton(kernelBox);
        activateKernel->setObjectName(QString::fromUtf8("activateKernel"));
        QIcon icon24;
        icon24.addFile(QString::fromUtf8(":/connect_creating.png"), QSize(), QIcon::Normal, QIcon::Off);
        activateKernel->setIcon(icon24);

        horizontalLayout_14->addWidget(activateKernel);

        label_17 = new QLabel(kernelBox);
        label_17->setObjectName(QString::fromUtf8("label_17"));

        horizontalLayout_14->addWidget(label_17);

        pid = new QLineEdit(kernelBox);
        pid->setObjectName(QString::fromUtf8("pid"));
        QSizePolicy sizePolicy5(QSizePolicy::Preferred, QSizePolicy::Fixed);
        sizePolicy5.setHorizontalStretch(0);
        sizePolicy5.setVerticalStretch(0);
        sizePolicy5.setHeightForWidth(pid->sizePolicy().hasHeightForWidth());
        pid->setSizePolicy(sizePolicy5);
        pid->setReadOnly(true);

        horizontalLayout_14->addWidget(pid);

        deactivateKernel = new QPushButton(kernelBox);
        deactivateKernel->setObjectName(QString::fromUtf8("deactivateKernel"));
        deactivateKernel->setIcon(icon1);

        horizontalLayout_14->addWidget(deactivateKernel);


        verticalLayout_12->addLayout(horizontalLayout_14);

        horizontalLayout_15 = new QHBoxLayout();
        horizontalLayout_15->setObjectName(QString::fromUtf8("horizontalLayout_15"));
        label_18 = new QLabel(kernelBox);
        label_18->setObjectName(QString::fromUtf8("label_18"));

        horizontalLayout_15->addWidget(label_18);

        kernelPath = new QLineEdit(kernelBox);
        kernelPath->setObjectName(QString::fromUtf8("kernelPath"));
        QSizePolicy sizePolicy6(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy6.setHorizontalStretch(0);
        sizePolicy6.setVerticalStretch(0);
        sizePolicy6.setHeightForWidth(kernelPath->sizePolicy().hasHeightForWidth());
        kernelPath->setSizePolicy(sizePolicy6);

        horizontalLayout_15->addWidget(kernelPath);

        selectKernelPath = new QPushButton(kernelBox);
        selectKernelPath->setObjectName(QString::fromUtf8("selectKernelPath"));

        horizontalLayout_15->addWidget(selectKernelPath);


        verticalLayout_12->addLayout(horizontalLayout_15);


        verticalLayout_4->addWidget(kernelBox);

        nodeName_2 = new QGroupBox(scrollAreaWidgetContents);
        nodeName_2->setObjectName(QString::fromUtf8("nodeName_2"));
        verticalLayout_11 = new QVBoxLayout(nodeName_2);
        verticalLayout_11->setObjectName(QString::fromUtf8("verticalLayout_11"));
        horizontalLayout_6 = new QHBoxLayout();
        horizontalLayout_6->setObjectName(QString::fromUtf8("horizontalLayout_6"));
        nodeName = new QLineEdit(nodeName_2);
        nodeName->setObjectName(QString::fromUtf8("nodeName"));

        horizontalLayout_6->addWidget(nodeName);

        saveNodeName = new QPushButton(nodeName_2);
        saveNodeName->setObjectName(QString::fromUtf8("saveNodeName"));

        horizontalLayout_6->addWidget(saveNodeName);


        verticalLayout_11->addLayout(horizontalLayout_6);


        verticalLayout_4->addWidget(nodeName_2);

        groupBox_2 = new QGroupBox(scrollAreaWidgetContents);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        verticalLayout_10 = new QVBoxLayout(groupBox_2);
        verticalLayout_10->setObjectName(QString::fromUtf8("verticalLayout_10"));
        horizontalLayout_9 = new QHBoxLayout();
        horizontalLayout_9->setObjectName(QString::fromUtf8("horizontalLayout_9"));
        ipv4Neighbor = new QRadioButton(groupBox_2);
        ipv4Neighbor->setObjectName(QString::fromUtf8("ipv4Neighbor"));

        horizontalLayout_9->addWidget(ipv4Neighbor);

        ipv6Neighbor = new QRadioButton(groupBox_2);
        ipv6Neighbor->setObjectName(QString::fromUtf8("ipv6Neighbor"));

        horizontalLayout_9->addWidget(ipv6Neighbor);


        verticalLayout_10->addLayout(horizontalLayout_9);

        horizontalLayout_10 = new QHBoxLayout();
        horizontalLayout_10->setObjectName(QString::fromUtf8("horizontalLayout_10"));
        neighborIP = new QLineEdit(groupBox_2);
        neighborIP->setObjectName(QString::fromUtf8("neighborIP"));

        horizontalLayout_10->addWidget(neighborIP);

        neighborPort = new QSpinBox(groupBox_2);
        neighborPort->setObjectName(QString::fromUtf8("neighborPort"));
        neighborPort->setMaximum(65535);
        neighborPort->setValue(4710);

        horizontalLayout_10->addWidget(neighborPort);


        verticalLayout_10->addLayout(horizontalLayout_10);

        horizontalLayout_11 = new QHBoxLayout();
        horizontalLayout_11->setObjectName(QString::fromUtf8("horizontalLayout_11"));
        addNeighbor = new QPushButton(groupBox_2);
        addNeighbor->setObjectName(QString::fromUtf8("addNeighbor"));

        horizontalLayout_11->addWidget(addNeighbor);

        neighborScopeId = new QLineEdit(groupBox_2);
        neighborScopeId->setObjectName(QString::fromUtf8("neighborScopeId"));

        horizontalLayout_11->addWidget(neighborScopeId);


        verticalLayout_10->addLayout(horizontalLayout_11);


        verticalLayout_4->addWidget(groupBox_2);

        listenersBox = new QGroupBox(scrollAreaWidgetContents);
        listenersBox->setObjectName(QString::fromUtf8("listenersBox"));
        verticalLayout_6 = new QVBoxLayout(listenersBox);
        verticalLayout_6->setObjectName(QString::fromUtf8("verticalLayout_6"));
        horizontalLayout_12 = new QHBoxLayout();
        horizontalLayout_12->setObjectName(QString::fromUtf8("horizontalLayout_12"));
        ipv4Listener = new QRadioButton(listenersBox);
        ipv4Listener->setObjectName(QString::fromUtf8("ipv4Listener"));
        ipv4Listener->setLayoutDirection(Qt::LeftToRight);
        ipv4Listener->setChecked(true);

        horizontalLayout_12->addWidget(ipv4Listener);

        ipv6Listener = new QRadioButton(listenersBox);
        ipv6Listener->setObjectName(QString::fromUtf8("ipv6Listener"));
        ipv6Listener->setLayoutDirection(Qt::LeftToRight);

        horizontalLayout_12->addWidget(ipv6Listener);

        listenerIPCombo = new QComboBox(listenersBox);
        listenerIPCombo->setObjectName(QString::fromUtf8("listenerIPCombo"));
        listenerIPCombo->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        horizontalLayout_12->addWidget(listenerIPCombo);


        verticalLayout_6->addLayout(horizontalLayout_12);

        horizontalLayout_16 = new QHBoxLayout();
        horizontalLayout_16->setObjectName(QString::fromUtf8("horizontalLayout_16"));
        label_11 = new QLabel(listenersBox);
        label_11->setObjectName(QString::fromUtf8("label_11"));
        QSizePolicy sizePolicy7(QSizePolicy::Minimum, QSizePolicy::Preferred);
        sizePolicy7.setHorizontalStretch(0);
        sizePolicy7.setVerticalStretch(0);
        sizePolicy7.setHeightForWidth(label_11->sizePolicy().hasHeightForWidth());
        label_11->setSizePolicy(sizePolicy7);
        label_11->setLayoutDirection(Qt::RightToLeft);

        horizontalLayout_16->addWidget(label_11);

        listenerIP = new QLineEdit(listenersBox);
        listenerIP->setObjectName(QString::fromUtf8("listenerIP"));

        horizontalLayout_16->addWidget(listenerIP);


        verticalLayout_6->addLayout(horizontalLayout_16);

        horizontalLayout_17 = new QHBoxLayout();
        horizontalLayout_17->setObjectName(QString::fromUtf8("horizontalLayout_17"));
        listenerScopeIdLabel = new QLabel(listenersBox);
        listenerScopeIdLabel->setObjectName(QString::fromUtf8("listenerScopeIdLabel"));

        horizontalLayout_17->addWidget(listenerScopeIdLabel);

        listenerScopeId = new QLineEdit(listenersBox);
        listenerScopeId->setObjectName(QString::fromUtf8("listenerScopeId"));

        horizontalLayout_17->addWidget(listenerScopeId);


        verticalLayout_6->addLayout(horizontalLayout_17);

        horizontalLayout_18 = new QHBoxLayout();
        horizontalLayout_18->setObjectName(QString::fromUtf8("horizontalLayout_18"));
        label_12 = new QLabel(listenersBox);
        label_12->setObjectName(QString::fromUtf8("label_12"));
        sizePolicy7.setHeightForWidth(label_12->sizePolicy().hasHeightForWidth());
        label_12->setSizePolicy(sizePolicy7);
        label_12->setLayoutDirection(Qt::RightToLeft);

        horizontalLayout_18->addWidget(label_12);

        listenerPort = new QSpinBox(listenersBox);
        listenerPort->setObjectName(QString::fromUtf8("listenerPort"));
        listenerPort->setMinimum(1);
        listenerPort->setMaximum(65535);
        listenerPort->setValue(4710);

        horizontalLayout_18->addWidget(listenerPort);

        addListener = new QPushButton(listenersBox);
        addListener->setObjectName(QString::fromUtf8("addListener"));
        addListener->setIcon(icon11);

        horizontalLayout_18->addWidget(addListener);


        verticalLayout_6->addLayout(horizontalLayout_18);


        verticalLayout_4->addWidget(listenersBox);

        passphraseGroupBox = new QGroupBox(scrollAreaWidgetContents);
        passphraseGroupBox->setObjectName(QString::fromUtf8("passphraseGroupBox"));
        verticalLayout_9 = new QVBoxLayout(passphraseGroupBox);
        verticalLayout_9->setObjectName(QString::fromUtf8("verticalLayout_9"));
        horizontalLayout_8 = new QHBoxLayout();
        horizontalLayout_8->setObjectName(QString::fromUtf8("horizontalLayout_8"));
        label_16 = new QLabel(passphraseGroupBox);
        label_16->setObjectName(QString::fromUtf8("label_16"));

        horizontalLayout_8->addWidget(label_16);

        saltLength = new QSpinBox(passphraseGroupBox);
        saltLength->setObjectName(QString::fromUtf8("saltLength"));
        saltLength->setMinimum(256);
        saltLength->setMaximum(999999999);

        horizontalLayout_8->addWidget(saltLength);


        verticalLayout_9->addLayout(horizontalLayout_8);

        horizontalLayout_7 = new QHBoxLayout();
        horizontalLayout_7->setObjectName(QString::fromUtf8("horizontalLayout_7"));
        label_23 = new QLabel(passphraseGroupBox);
        label_23->setObjectName(QString::fromUtf8("label_23"));

        horizontalLayout_7->addWidget(label_23);

        rsaKeySize = new QComboBox(passphraseGroupBox);
        rsaKeySize->setObjectName(QString::fromUtf8("rsaKeySize"));

        horizontalLayout_7->addWidget(rsaKeySize);


        verticalLayout_9->addLayout(horizontalLayout_7);

        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setObjectName(QString::fromUtf8("horizontalLayout_5"));
        label_15 = new QLabel(passphraseGroupBox);
        label_15->setObjectName(QString::fromUtf8("label_15"));

        horizontalLayout_5->addWidget(label_15);

        iterationCount = new QSpinBox(passphraseGroupBox);
        iterationCount->setObjectName(QString::fromUtf8("iterationCount"));
        iterationCount->setMinimum(1000);
        iterationCount->setMaximum(999999999);
        iterationCount->setValue(10000);

        horizontalLayout_5->addWidget(iterationCount);


        verticalLayout_9->addLayout(horizontalLayout_5);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        label_14 = new QLabel(passphraseGroupBox);
        label_14->setObjectName(QString::fromUtf8("label_14"));

        horizontalLayout_4->addWidget(label_14);

        hashType = new QComboBox(passphraseGroupBox);
        hashType->setObjectName(QString::fromUtf8("hashType"));

        horizontalLayout_4->addWidget(hashType);


        verticalLayout_9->addLayout(horizontalLayout_4);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        label = new QLabel(passphraseGroupBox);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout_2->addWidget(label);

        cipherType = new QComboBox(passphraseGroupBox);
        cipherType->setObjectName(QString::fromUtf8("cipherType"));

        horizontalLayout_2->addWidget(cipherType);


        verticalLayout_9->addLayout(horizontalLayout_2);

        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        label_55 = new QLabel(passphraseGroupBox);
        label_55->setObjectName(QString::fromUtf8("label_55"));

        gridLayout->addWidget(label_55, 0, 0, 1, 1);

        label_58 = new QLabel(passphraseGroupBox);
        label_58->setObjectName(QString::fromUtf8("label_58"));

        gridLayout->addWidget(label_58, 0, 2, 1, 1);

        passphrase1 = new QLineEdit(passphraseGroupBox);
        passphrase1->setObjectName(QString::fromUtf8("passphrase1"));
        passphrase1->setEchoMode(QLineEdit::Password);

        gridLayout->addWidget(passphrase1, 0, 1, 1, 1);

        label_56 = new QLabel(passphraseGroupBox);
        label_56->setObjectName(QString::fromUtf8("label_56"));

        gridLayout->addWidget(label_56, 2, 0, 1, 1);

        passphrase2 = new QLineEdit(passphraseGroupBox);
        passphrase2->setObjectName(QString::fromUtf8("passphrase2"));
        passphrase2->setEchoMode(QLineEdit::Password);

        gridLayout->addWidget(passphrase2, 2, 1, 1, 1);

        setPassphrase = new QPushButton(passphraseGroupBox);
        setPassphrase->setObjectName(QString::fromUtf8("setPassphrase"));
        setPassphrase->setIcon(icon7);

        gridLayout->addWidget(setPassphrase, 2, 2, 1, 1);


        verticalLayout_9->addLayout(gridLayout);


        verticalLayout_4->addWidget(passphraseGroupBox);


        horizontalLayout_26->addLayout(verticalLayout_4);

        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout_15->addWidget(scrollArea);

        QIcon icon25;
        icon25.addFile(QString::fromUtf8(":/tab-settings.png"), QSize(), QIcon::Normal, QIcon::Off);
        tab->addTab(tab_settings, icon25, QString());
        tab_login = new QWidget();
        tab_login->setObjectName(QString::fromUtf8("tab_login"));
        horizontalLayout_34 = new QHBoxLayout(tab_login);
        horizontalLayout_34->setObjectName(QString::fromUtf8("horizontalLayout_34"));
        verticalLayout_5 = new QVBoxLayout();
        verticalLayout_5->setObjectName(QString::fromUtf8("verticalLayout_5"));
        verticalSpacer_5 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_5->addItem(verticalSpacer_5);

        horizontalLayout_32 = new QHBoxLayout();
        horizontalLayout_32->setObjectName(QString::fromUtf8("horizontalLayout_32"));
        horizontalSpacer_35 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_32->addItem(horizontalSpacer_35);

        label_31 = new QLabel(tab_login);
        label_31->setObjectName(QString::fromUtf8("label_31"));
        label_31->setPixmap(QPixmap(QString::fromUtf8(":/Logo/spoton-dalmatinerlogo.png")));
        label_31->setAlignment(Qt::AlignCenter);

        horizontalLayout_32->addWidget(label_31);

        horizontalSpacer_34 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_32->addItem(horizontalSpacer_34);


        verticalLayout_5->addLayout(horizontalLayout_32);

        horizontalLayout_13 = new QHBoxLayout();
        horizontalLayout_13->setObjectName(QString::fromUtf8("horizontalLayout_13"));
        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_13->addItem(horizontalSpacer_6);

        passphraseLabel = new QLabel(tab_login);
        passphraseLabel->setObjectName(QString::fromUtf8("passphraseLabel"));

        horizontalLayout_13->addWidget(passphraseLabel);

        passphrase = new QLineEdit(tab_login);
        passphrase->setObjectName(QString::fromUtf8("passphrase"));
        passphrase->setEchoMode(QLineEdit::Password);

        horizontalLayout_13->addWidget(passphrase);

        passphraseButton = new QPushButton(tab_login);
        passphraseButton->setObjectName(QString::fromUtf8("passphraseButton"));
        passphraseButton->setIcon(icon7);

        horizontalLayout_13->addWidget(passphraseButton);

        horizontalSpacer_9 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_13->addItem(horizontalSpacer_9);


        verticalLayout_5->addLayout(horizontalLayout_13);

        verticalSpacer_7 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_5->addItem(verticalSpacer_7);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer);

        label_4 = new QLabel(tab_login);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setMaximumSize(QSize(485, 240));
        label_4->setPixmap(QPixmap(QString::fromUtf8(":/Logo/spoton-logo-transparent.png")));
        label_4->setScaledContents(true);
        label_4->setAlignment(Qt::AlignCenter);

        horizontalLayout_3->addWidget(label_4);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_2);


        verticalLayout_5->addLayout(horizontalLayout_3);

        verticalSpacer_2 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_5->addItem(verticalSpacer_2);


        horizontalLayout_34->addLayout(verticalLayout_5);

        tab->addTab(tab_login, icon, QString());

        verticalLayout_3->addWidget(tab);

        spoton_mainwindow->setCentralWidget(centralwidget);
        statusbar = new QStatusBar(spoton_mainwindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        spoton_mainwindow->setStatusBar(statusbar);
        menubar = new QMenuBar(spoton_mainwindow);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 624, 26));
        menu_File = new QMenu(menubar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        spoton_mainwindow->setMenuBar(menubar);
#ifndef QT_NO_SHORTCUT
        label_from->setBuddy(mailFrom);
        label_30->setBuddy(mailMessage);
        label_29->setBuddy(mailSubject);
        label_10->setBuddy(participantsCombo);
        label_25->setBuddy(outgoingSubject);
        label_26->setBuddy(outgoingMessage);
        label_6->setBuddy(goldbug);
        label_18->setBuddy(kernelPath);
        label_11->setBuddy(listenerIP);
        listenerScopeIdLabel->setBuddy(listenerScopeId);
        label_12->setBuddy(listenerPort);
        label_16->setBuddy(saltLength);
        label_23->setBuddy(rsaKeySize);
        label_15->setBuddy(iterationCount);
        label_14->setBuddy(hashType);
        label->setBuddy(cipherType);
        label_55->setBuddy(passphrase1);
        label_56->setBuddy(passphrase2);
        passphraseLabel->setBuddy(passphrase);
#endif // QT_NO_SHORTCUT
        QWidget::setTabOrder(tab, messages);
        QWidget::setTabOrder(messages, participants);
        QWidget::setTabOrder(participants, mailTab);
        QWidget::setTabOrder(mailTab, folder);
        QWidget::setTabOrder(folder, retrieveMail);
        QWidget::setTabOrder(retrieveMail, refreshMail);
        QWidget::setTabOrder(refreshMail, deleteMail);
        QWidget::setTabOrder(deleteMail, emptyTrash);
        QWidget::setTabOrder(emptyTrash, mail);
        QWidget::setTabOrder(mail, mailFrom);
        QWidget::setTabOrder(mailFrom, mailSubject);
        QWidget::setTabOrder(mailSubject, mailMessage);
        QWidget::setTabOrder(mailMessage, sendMail);
        QWidget::setTabOrder(sendMail, pushButtonClearOutgoingMessage);
        QWidget::setTabOrder(pushButtonClearOutgoingMessage, participantsCombo);
        QWidget::setTabOrder(participantsCombo, outgoingSubject);
        QWidget::setTabOrder(outgoingSubject, outgoingMessage);
        QWidget::setTabOrder(outgoingMessage, goldbug);
        QWidget::setTabOrder(goldbug, generateGoldBug);
        QWidget::setTabOrder(generateGoldBug, addFriendPublicKeyRadio);
        QWidget::setTabOrder(addFriendPublicKeyRadio, addFriendSymmetricBundleRadio);
        QWidget::setTabOrder(addFriendSymmetricBundleRadio, friendInformation);
        QWidget::setTabOrder(friendInformation, addFriend);
        QWidget::setTabOrder(addFriend, clearFriend);
        QWidget::setTabOrder(clearFriend, scrollArea);
        QWidget::setTabOrder(scrollArea, activateKernel);
        QWidget::setTabOrder(activateKernel, pid);
        QWidget::setTabOrder(pid, deactivateKernel);
        QWidget::setTabOrder(deactivateKernel, kernelPath);
        QWidget::setTabOrder(kernelPath, selectKernelPath);
        QWidget::setTabOrder(selectKernelPath, ipv4Listener);
        QWidget::setTabOrder(ipv4Listener, ipv6Listener);
        QWidget::setTabOrder(ipv6Listener, listenerIP);
        QWidget::setTabOrder(listenerIP, listenerScopeId);
        QWidget::setTabOrder(listenerScopeId, listenerPort);
        QWidget::setTabOrder(listenerPort, addListener);
        QWidget::setTabOrder(addListener, cipherType);
        QWidget::setTabOrder(cipherType, hashType);
        QWidget::setTabOrder(hashType, iterationCount);
        QWidget::setTabOrder(iterationCount, rsaKeySize);
        QWidget::setTabOrder(rsaKeySize, saltLength);
        QWidget::setTabOrder(saltLength, passphrase1);
        QWidget::setTabOrder(passphrase1, passphrase2);
        QWidget::setTabOrder(passphrase2, setPassphrase);
        QWidget::setTabOrder(setPassphrase, passphrase);
        QWidget::setTabOrder(passphrase, passphraseButton);

        menubar->addAction(menu_File->menuAction());
        menu_File->addAction(action_Quit);

        retranslateUi(spoton_mainwindow);

        tab->setCurrentIndex(4);
        status->setCurrentIndex(0);
        mailTab->setCurrentIndex(0);
        rsaKeySize->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(spoton_mainwindow);
    } // setupUi

    void retranslateUi(QMainWindow *spoton_mainwindow)
    {
        spoton_mainwindow->setWindowTitle(QApplication::translate("spoton_mainwindow", "Spot-On", 0, QApplication::UnicodeUTF8));
        action_Quit->setText(QApplication::translate("spoton_mainwindow", "&Quit", 0, QApplication::UnicodeUTF8));
        action_Quit->setShortcut(QApplication::translate("spoton_mainwindow", "Ctrl+Q", 0, QApplication::UnicodeUTF8));
        action_Log_Viewer->setText(QApplication::translate("spoton_mainwindow", "&Log Viewer", 0, QApplication::UnicodeUTF8));
        action_Log_Viewer->setShortcut(QApplication::translate("spoton_mainwindow", "Ctrl+L", 0, QApplication::UnicodeUTF8));
        groupBox_9->setTitle(QApplication::translate("spoton_mainwindow", "Messages", 0, QApplication::UnicodeUTF8));
        status->setItemText(0, QApplication::translate("spoton_mainwindow", "Away", 0, QApplication::UnicodeUTF8));
        status->setItemText(1, QApplication::translate("spoton_mainwindow", "Busy", 0, QApplication::UnicodeUTF8));
        status->setItemText(2, QApplication::translate("spoton_mainwindow", "Offline", 0, QApplication::UnicodeUTF8));
        status->setItemText(3, QApplication::translate("spoton_mainwindow", "Online", 0, QApplication::UnicodeUTF8));

        sendMessage->setText(QApplication::translate("spoton_mainwindow", "Send", 0, QApplication::UnicodeUTF8));
        groupBox->setTitle(QApplication::translate("spoton_mainwindow", "Friends", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem = participants->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QApplication::translate("spoton_mainwindow", "Participant", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem1 = participants->horizontalHeaderItem(1);
        ___qtablewidgetitem1->setText(QApplication::translate("spoton_mainwindow", "OID", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem2 = participants->horizontalHeaderItem(2);
        ___qtablewidgetitem2->setText(QApplication::translate("spoton_mainwindow", "neighbor_oid", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem3 = participants->horizontalHeaderItem(3);
        ___qtablewidgetitem3->setText(QApplication::translate("spoton_mainwindow", "public_key_hash", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem4 = participants->horizontalHeaderItem(4);
        ___qtablewidgetitem4->setText(QApplication::translate("spoton_mainwindow", "Status", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem5 = participants->horizontalHeaderItem(5);
        ___qtablewidgetitem5->setText(QApplication::translate("spoton_mainwindow", "Gemini", 0, QApplication::UnicodeUTF8));
        tab->setTabText(tab->indexOf(tab_chat), QString());
        tab->setTabToolTip(tab->indexOf(tab_chat), QApplication::translate("spoton_mainwindow", "Chat", 0, QApplication::UnicodeUTF8));
        groupBox_addkey_2->setTitle(QApplication::translate("spoton_mainwindow", "Add Participant", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        toolButtonCopytoClipboard->setToolTip(QApplication::translate("spoton_mainwindow", "<html><head/><body><p>Copy my name and specified public key to the clipboard buffer.</p></body></html>", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        toolButtonCopytoClipboard->setText(QApplication::translate("spoton_mainwindow", "Copy Key", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        addFriendPublicKeyRadio->setToolTip(QApplication::translate("spoton_mainwindow", "<html><head/><body><p>The key must start with either the letter K or the letter k.</p></body></html>", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        addFriendPublicKeyRadio->setText(QApplication::translate("spoton_mainwindow", "&Key", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        addFriendSymmetricBundleRadio->setToolTip(QApplication::translate("spoton_mainwindow", "<html><head/><body><p>The repleo must start with either the letter R or the letter r.</p></body></html>", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        addFriendSymmetricBundleRadio->setText(QApplication::translate("spoton_mainwindow", "&Repleo", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        addFriend->setToolTip(QApplication::translate("spoton_mainwindow", "<html><head/><body><p>Add Participant via <span style=\" font-weight:600;\">IP Connection</span></p><ol style=\"margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;\"><li style=\" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Add a listener. See the Settings tab. You may be required to forward the port in your router.</li><li style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Send the connection information to the participant.</li><li style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Once connected, at least one user must share the public key via the context menu in the Neighbors table.</li><li style=\" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Confirm participants via the context menu in the Chat tab's Part"
                        "icipants table.</li></ol><p>Add Participant with <span style=\" font-weight:600;\">Repleo Exchange</span></p><ol style=\"margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;\"><li style=\" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Obtain the public key from participant. Paste it in the above textbox. Click the Key radio button and press the Add button.</li><li style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Copy the Repleo of the new participant from the context menu in the Chat tab's Participants table.</li><li style=\" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Send the Repleo.</li></ol></body></html>", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        addFriend->setText(QApplication::translate("spoton_mainwindow", "Add", 0, QApplication::UnicodeUTF8));
        clearFriend->setText(QApplication::translate("spoton_mainwindow", "Clear", 0, QApplication::UnicodeUTF8));
        tab->setTabText(tab->indexOf(tab_neighbors), QString());
        tab->setTabToolTip(tab->indexOf(tab_neighbors), QApplication::translate("spoton_mainwindow", "Neighbors", 0, QApplication::UnicodeUTF8));
        folder->setItemText(0, QApplication::translate("spoton_mainwindow", "Inbox", 0, QApplication::UnicodeUTF8));
        folder->setItemText(1, QApplication::translate("spoton_mainwindow", "Sent", 0, QApplication::UnicodeUTF8));
        folder->setItemText(2, QApplication::translate("spoton_mainwindow", "Trash", 0, QApplication::UnicodeUTF8));

        retrieveMail->setText(QApplication::translate("spoton_mainwindow", "Retrieve", 0, QApplication::UnicodeUTF8));
        refreshMail->setText(QApplication::translate("spoton_mainwindow", "Refresh", 0, QApplication::UnicodeUTF8));
        deleteMail->setText(QApplication::translate("spoton_mainwindow", "Delete", 0, QApplication::UnicodeUTF8));
        emptyTrash->setText(QApplication::translate("spoton_mainwindow", "Empty Trash", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem6 = mail->horizontalHeaderItem(0);
        ___qtablewidgetitem6->setText(QApplication::translate("spoton_mainwindow", "Date", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem7 = mail->horizontalHeaderItem(1);
        ___qtablewidgetitem7->setText(QApplication::translate("spoton_mainwindow", "From", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem8 = mail->horizontalHeaderItem(2);
        ___qtablewidgetitem8->setText(QApplication::translate("spoton_mainwindow", "Status", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem9 = mail->horizontalHeaderItem(3);
        ___qtablewidgetitem9->setText(QApplication::translate("spoton_mainwindow", "Subject", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem10 = mail->horizontalHeaderItem(4);
        ___qtablewidgetitem10->setText(QApplication::translate("spoton_mainwindow", "message", 0, QApplication::UnicodeUTF8));
        QTableWidgetItem *___qtablewidgetitem11 = mail->horizontalHeaderItem(5);
        ___qtablewidgetitem11->setText(QApplication::translate("spoton_mainwindow", "OID", 0, QApplication::UnicodeUTF8));
        label_from->setText(QApplication::translate("spoton_mainwindow", "&From", 0, QApplication::UnicodeUTF8));
        label_30->setText(QApplication::translate("spoton_mainwindow", "&Message", 0, QApplication::UnicodeUTF8));
        label_29->setText(QApplication::translate("spoton_mainwindow", "&Subject", 0, QApplication::UnicodeUTF8));
        mailTab->setTabText(mailTab->indexOf(tab_4), QApplication::translate("spoton_mainwindow", "&Read", 0, QApplication::UnicodeUTF8));
        sendMail->setText(QApplication::translate("spoton_mainwindow", "Send", 0, QApplication::UnicodeUTF8));
        pushButtonClearOutgoingMessage->setText(QApplication::translate("spoton_mainwindow", "Clear", 0, QApplication::UnicodeUTF8));
        label_10->setText(QApplication::translate("spoton_mainwindow", "&To", 0, QApplication::UnicodeUTF8));
        participantsCombo->setItemText(0, QApplication::translate("spoton_mainwindow", "All Participants", 0, QApplication::UnicodeUTF8));

        label_25->setText(QApplication::translate("spoton_mainwindow", "&Subject", 0, QApplication::UnicodeUTF8));
        label_26->setText(QApplication::translate("spoton_mainwindow", "&Message", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        generateGoldBug->setToolTip(QApplication::translate("spoton_mainwindow", "<html><head/><body><p>Generate a random Gold Bug (AES-256). The Gold Bug will apply an additional layer of encryption to the message. Please remember to notify all recipients of your Gold Bug.</p></body></html>", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        generateGoldBug->setText(QApplication::translate("spoton_mainwindow", "Generate Gold Bug", 0, QApplication::UnicodeUTF8));
        label_6->setText(QApplication::translate("spoton_mainwindow", "&Optional", 0, QApplication::UnicodeUTF8));
        mailTab->setTabText(mailTab->indexOf(tab_5), QApplication::translate("spoton_mainwindow", "&Write", 0, QApplication::UnicodeUTF8));
        tab->setTabText(tab->indexOf(tab_email), QString());
        tab->setTabToolTip(tab->indexOf(tab_email), QApplication::translate("spoton_mainwindow", "E-Mail", 0, QApplication::UnicodeUTF8));
        kernelBox->setTitle(QApplication::translate("spoton_mainwindow", "Kernel", 0, QApplication::UnicodeUTF8));
        activateKernel->setText(QApplication::translate("spoton_mainwindow", "Activate", 0, QApplication::UnicodeUTF8));
        label_17->setText(QApplication::translate("spoton_mainwindow", "PID", 0, QApplication::UnicodeUTF8));
        pid->setText(QApplication::translate("spoton_mainwindow", "0", 0, QApplication::UnicodeUTF8));
        deactivateKernel->setText(QApplication::translate("spoton_mainwindow", "Deactivate", 0, QApplication::UnicodeUTF8));
        label_18->setText(QApplication::translate("spoton_mainwindow", "Path of Spot-On-Kernel &Executable", 0, QApplication::UnicodeUTF8));
        selectKernelPath->setText(QApplication::translate("spoton_mainwindow", "Select", 0, QApplication::UnicodeUTF8));
        nodeName_2->setTitle(QApplication::translate("spoton_mainwindow", "Set your Nick Name", 0, QApplication::UnicodeUTF8));
        saveNodeName->setText(QApplication::translate("spoton_mainwindow", "saveNodeName", 0, QApplication::UnicodeUTF8));
        groupBox_2->setTitle(QApplication::translate("spoton_mainwindow", "Connect to Server", 0, QApplication::UnicodeUTF8));
        ipv4Neighbor->setText(QApplication::translate("spoton_mainwindow", "IPv4", 0, QApplication::UnicodeUTF8));
        ipv6Neighbor->setText(QApplication::translate("spoton_mainwindow", "IPv6", 0, QApplication::UnicodeUTF8));
        addNeighbor->setText(QApplication::translate("spoton_mainwindow", "addNeighbor", 0, QApplication::UnicodeUTF8));
        listenersBox->setTitle(QApplication::translate("spoton_mainwindow", "Create own Server", 0, QApplication::UnicodeUTF8));
        ipv4Listener->setText(QApplication::translate("spoton_mainwindow", "IPv&4", 0, QApplication::UnicodeUTF8));
        ipv6Listener->setText(QApplication::translate("spoton_mainwindow", "IPv&6", 0, QApplication::UnicodeUTF8));
        listenerIPCombo->clear();
        listenerIPCombo->insertItems(0, QStringList()
         << QApplication::translate("spoton_mainwindow", "Custom", 0, QApplication::UnicodeUTF8)
        );
        label_11->setText(QApplication::translate("spoton_mainwindow", "&IP", 0, QApplication::UnicodeUTF8));
        listenerScopeIdLabel->setText(QApplication::translate("spoton_mainwindow", "&Scope ID", 0, QApplication::UnicodeUTF8));
        label_12->setText(QApplication::translate("spoton_mainwindow", "&Port", 0, QApplication::UnicodeUTF8));
        addListener->setText(QApplication::translate("spoton_mainwindow", "Add", 0, QApplication::UnicodeUTF8));
        passphraseGroupBox->setTitle(QApplication::translate("spoton_mainwindow", "Passphrase", 0, QApplication::UnicodeUTF8));
        label_16->setText(QApplication::translate("spoton_mainwindow", "Salt &Length", 0, QApplication::UnicodeUTF8));
        label_23->setText(QApplication::translate("spoton_mainwindow", "&RSA Key Size", 0, QApplication::UnicodeUTF8));
        rsaKeySize->clear();
        rsaKeySize->insertItems(0, QStringList()
         << QApplication::translate("spoton_mainwindow", "3072", 0, QApplication::UnicodeUTF8)
         << QApplication::translate("spoton_mainwindow", "7680", 0, QApplication::UnicodeUTF8)
         << QApplication::translate("spoton_mainwindow", "15360", 0, QApplication::UnicodeUTF8)
        );
        label_15->setText(QApplication::translate("spoton_mainwindow", "Iteration &Count", 0, QApplication::UnicodeUTF8));
        label_14->setText(QApplication::translate("spoton_mainwindow", "&Hash", 0, QApplication::UnicodeUTF8));
        label->setText(QApplication::translate("spoton_mainwindow", "&Cipher", 0, QApplication::UnicodeUTF8));
        label_55->setText(QApplication::translate("spoton_mainwindow", "P&assphrase", 0, QApplication::UnicodeUTF8));
        label_58->setText(QApplication::translate("spoton_mainwindow", "Minimum of 16 characters.", 0, QApplication::UnicodeUTF8));
        label_56->setText(QApplication::translate("spoton_mainwindow", "P&assphrase Confirmation", 0, QApplication::UnicodeUTF8));
        setPassphrase->setText(QApplication::translate("spoton_mainwindow", "Set Passphrase", 0, QApplication::UnicodeUTF8));
        tab->setTabText(tab->indexOf(tab_settings), QString());
        tab->setTabToolTip(tab->indexOf(tab_settings), QApplication::translate("spoton_mainwindow", "Settings", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        label_31->setToolTip(QApplication::translate("spoton_mainwindow", "<html><head/><body><p>&quot;The Dalmatian is a breed of dog, noted for its unique black- or brown-spotted coat. This dog is often used as a rescue dog, guardian, athletic partner, and, especially today, the Dalmatian remains most often an active, well-loved family member.&quot; - Wikipedia.</p></body></html>", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        label_31->setText(QString());
        passphraseLabel->setText(QApplication::translate("spoton_mainwindow", "P&assphrase", 0, QApplication::UnicodeUTF8));
        passphraseButton->setText(QApplication::translate("spoton_mainwindow", "Authenticate", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        label_4->setToolTip(QApplication::translate("spoton_mainwindow", "Spot-On Graphical User Interface Version 1.00", 0, QApplication::UnicodeUTF8));
#endif // QT_NO_TOOLTIP
        tab->setTabText(tab->indexOf(tab_login), QString());
        menu_File->setTitle(QApplication::translate("spoton_mainwindow", "&File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class spoton_mainwindow: public Ui_spoton_mainwindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CONTROLCENTER_H
