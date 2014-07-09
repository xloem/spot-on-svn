/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from Spot-On without specific prior written permission.
**
** SPOT-ON IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** SPOT-ON, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "Common/spot-on-misc.h"
#include "spot-on.h"
#include "spot-on-chatwindow.h"
#include "spot-on-defines.h"

#include <QDateTime>
#if SPOTON_GOLDBUG == 1
#if QT_VERSION >= 0x050000
#include <QMediaPlayer>
#endif
#endif
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>

spoton_chatwindow::spoton_chatwindow(const QIcon &icon,
				     const QString &id,
				     const QString &participant,
				     QSslSocket *kernelSocket,
				     QWidget *parent):QMainWindow(parent)
{
  m_id = id;
  m_kernelSocket = kernelSocket;
  ui.setupUi(this);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#if QT_VERSION >= 0x050000
  setWindowFlags(windowFlags() & ~Qt::WindowFullscreenButtonHint);
#endif
  statusBar()->setSizeGripEnabled(false);
#endif
  connect(ui.clearMessages,
	  SIGNAL(clicked(void)),
	  ui.messages,
	  SLOT(clear(void)));
  connect(ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));

  if(participant.trimmed().isEmpty())
    setWindowTitle(tr("%1: %2").
		   arg(SPOTON_APPLICATION_NAME).
		   arg("unknown"));
  else
    setWindowTitle(tr("%1: %2").
		   arg(SPOTON_APPLICATION_NAME).
		   arg(participant.trimmed()));

  ui.icon->setPixmap(icon.pixmap(QSize(16, 16)));

  if(participant.trimmed().isEmpty())
    ui.name->setText("unknown");
  else
    ui.name->setText(participant.trimmed());

  slotSetIcons();
}

spoton_chatwindow::~spoton_chatwindow()
{
}

void spoton_chatwindow::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nouve").toString());

  ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.sendMessage->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

QString spoton_chatwindow::id(void) const
{
  return m_id;
}

void spoton_chatwindow::closeEvent(QCloseEvent *event)
{
  QMainWindow::closeEvent(event);
}

void spoton_chatwindow::center(QWidget *parent)
{
  if(!parent)
    return;

  QPoint p(parent->pos());
  int X = 0;
  int Y = 0;

  if(parent->width() >= width())
    X = p.x() + (parent->width() - width()) / 2;
  else
    X = p.x() - (width() - parent->width()) / 2;

  if(parent->height() >= height())
    Y = p.y() + (parent->height() - height()) / 2;
  else
    Y = p.y() - (height() - parent->height()) / 2;

  move(X, Y);
}

void spoton_chatwindow::slotSendMessage(void)
{
  QByteArray message;
  QByteArray name;
  QDateTime now(QDateTime::currentDateTime());
  QString error("");

  if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      error = tr("Not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket->isEncrypted())
    {
      error = tr("The connection to the kernel is not encrypted.");
      goto done_label;
    }
  else if(ui.message->toPlainText().trimmed().isEmpty())
    {
      error = tr("Please provide a real message.");
      goto done_label;
    }

  name = spoton::s_gui->m_settings.
    value("gui/nodeName", "unknown").toByteArray().trimmed();
  message.append
    (QString("[%1:%2<font color=grey>:%3</font>] ").
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText().trimmed());
  ui.messages->append(message);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());
  spoton::s_gui->ui().messages->append(message);
  spoton::s_gui->ui().messages->verticalScrollBar()->setValue
    (spoton::s_gui->ui().messages->verticalScrollBar()->maximum());
  message.clear();

  if(name.isEmpty())
    name = "unknown";

  spoton::s_gui->m_chatSequenceNumbers[m_id] += 1;
  message.append("message_");
  message.append(QString("%1_").arg(m_id));
  message.append(name.toBase64());
  message.append("_");
  message.append(ui.message->toPlainText().trimmed().toUtf8().
		 toBase64());
  message.append("_");
  message.append
    (QByteArray::number(spoton::s_gui->m_chatSequenceNumbers[m_id]).
     toBase64());
  message.append("_");
  message.append(QDateTime::currentDateTime().toUTC().
		 toString("hhmmss").toLatin1().toBase64());
  message.append('\n');

  if(m_kernelSocket->write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton_chatwindow::slotSendMessage(): write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket->peerAddress().toString()).
       arg(m_kernelSocket->peerPort()));
  else
    emit messageSent();

  ui.message->clear();

 done_label:

#if SPOTON_GOLDBUG == 1
#if QT_VERSION >= 0x050000
  QMediaPlayer *player = 0;
  QString str
    (QDir::cleanPath(QCoreApplication::applicationDirPath() +
		     QDir::separator() + "Sounds" + QDir::separator() +
		     "send.wav"));

  player = findChild<QMediaPlayer *> ("send.wav");

  if(!player)
    player = new QMediaPlayer(this);

  player->setMedia(QUrl::fromLocalFile(str));
  player->setObjectName("send.wav");
  player->setVolume(50);
  player->play();
#endif
#endif

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
}

void spoton_chatwindow::append(const QString &text)
{
  ui.messages->append(text);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());
}

void spoton_chatwindow::slotSetStatus(const QIcon &icon,
				      const QString &name,
				      const QString &id)
{
  if(id == m_id)
    {
      if(!icon.isNull())
	ui.icon->setPixmap(icon.pixmap(QSize(16, 16)));

      if(!name.trimmed().isEmpty())
	{
	  setWindowTitle
	    (tr("%1: %2").
	     arg(SPOTON_APPLICATION_NAME).
	     arg(name.trimmed()));
	  ui.name->setText(name.trimmed());
	}
      else
	{
	  setWindowTitle(tr("%1: %2").
			 arg(SPOTON_APPLICATION_NAME).
			 arg("unknown"));
	  ui.name->setText("unknown");
	}
    }
}

void spoton_chatwindow::setName(const QString &name)
{
  if(!name.trimmed().isEmpty())
    {
      setWindowTitle(tr("%1: %2").
		     arg(SPOTON_APPLICATION_NAME).
		     arg(name.trimmed()));
      ui.name->setText(name.trimmed());
    }
  else
    {
      setWindowTitle(tr("%1: %2").
		     arg(SPOTON_APPLICATION_NAME).
		     arg("unknown"));
      ui.name->setText("unknown");
    }
}

void spoton_chatwindow::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_chatwindow::event(QEvent *event)
{
  if(event)
    if(event->type() == QEvent::WindowStateChange)
      if(windowState() == Qt::WindowNoState)
	{
	  /*
	  ** Minimizing the window on OS 10.6.8 and Qt 5.x will cause
	  ** the window to become stale once it has resurfaced.
	  */

	  hide();
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif
