/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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

#include <QDateTime>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>

#include "Common/spot-on-misc.h"
#include "spot-on-chatwindow.h"

spoton_chatwindow::spoton_chatwindow(const QIcon &icon,
				     const QString &id,
				     const QString &participant,
				     QSslSocket *kernelSocket,
				     QWidget *parent):QMainWindow(parent)
{
  m_id = id;
  m_kernelSocket = kernelSocket;
  ui.setupUi(this);
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
    setWindowTitle(tr("Spot-On: %1").arg("unknown"));
  else
    setWindowTitle(tr("Spot-On: %1").arg(participant));

  ui.icon->setPixmap(icon.pixmap(QSize(16, 16)));

  if(participant.trimmed().isEmpty())
    ui.name->setText("unknown");
  else
    ui.name->setText(participant);

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

  if(parentWidget()->width() >= width())
    X = p.x() + (parentWidget()->width() - width()) / 2;
  else
    X = p.x() - (width() - parentWidget()->width()) / 2;

  if(parentWidget()->height() >= height())
    Y = p.y() + (parentWidget()->height() - height()) / 2;
  else
    Y = p.y() - (height() - parentWidget()->height()) / 2;

  move(X, Y);
}

void spoton_chatwindow::slotSendMessage(void)
{
  QByteArray message;
  QByteArray name;
  QSettings settings;
  QString error("");

  if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      error = tr("Not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket->isEncrypted())
    {
      error = tr("Connection to the kernel is not encrypted.");
      goto done_label;
    }
  else if(ui.message->toPlainText().trimmed().isEmpty())
    {
      error = tr("Please provide a message.");
      goto done_label;
    }

  name = settings.value("gui/nodeName", "unknown").toByteArray().trimmed();
  message.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText().trimmed());
  ui.messages->append(message);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());
  message.clear();

  if(name.isEmpty())
    name = "unknown";

  message.append("message_");
  message.append(QString("%1_").arg(m_id));
  message.append(name.toBase64());
  message.append("_");
  message.append(ui.message->toPlainText().trimmed().toUtf8().
		 toBase64());
  message.append('\n');

  if(m_kernelSocket->write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton_chatwindow::slotSendMessage(): write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket->peerAddress().toString()).
       arg(m_kernelSocket->peerPort()));
  else
    {
      m_kernelSocket->flush();
      emit messageSent();
    }

  ui.message->clear();

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
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
	ui.name->setText(name);
    }
}
