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
#include <QScrollBar>
#include <QSettings>

#include "Common/spot-on-misc.h"
#include "spot-on-buzzpage.h"

spoton_buzzpage::spoton_buzzpage(QTcpSocket *kernelSocket,
				 const QByteArray &id,
				 QWidget *parent):QWidget(parent)
{
  m_id = id;
  m_kernelSocket = kernelSocket;
  ui.setupUi(this);
  connect(ui.clearMessages,
	  SIGNAL(clicked(void)),
	  ui.messages,
	  SLOT(clear(void)));
  connect(ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  ui.clients->setColumnHidden(1, true); // ID
  ui.splitter->setStretchFactor(0, 1);
  ui.splitter->setStretchFactor(1, 0);
  slotSetIcons();
}

spoton_buzzpage::~spoton_buzzpage()
{
}

void spoton_buzzpage::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nouve").toString());

  ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.sendMessage->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

void spoton_buzzpage::slotSendMessage(void)
{
  if(!m_kernelSocket)
    return;
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    return;
  else if(ui.message->toPlainText().trimmed().isEmpty())
    return;

  QByteArray name;
  QByteArray message;
  QByteArray sendMethod;
  QSettings settings;

  message.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText().trimmed());
  ui.messages->append(message);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());

  if(ui.sendMethod->currentIndex() == 0)
    sendMethod = "Normal_POST";
  else
    sendMethod = "Artificial_GET";

  name = settings.value("gui/buzzName", "unknown").toByteArray().trimmed();

  if(name.isEmpty())
    name = "unknown";

  message.clear();
  message.append("buzz_");
  message.append(name.toBase64());
  message.append("_");
  message.append(m_id.toBase64());
  message.append("_");
  message.append(ui.message->toPlainText().trimmed().toUtf8().
		 toBase64());
  message.append("_");
  message.append(sendMethod.toBase64());
  message.append('\n');

  if(m_kernelSocket->write(message.constData(),
			   message.length()) != message.length())
    spoton_misc::logError
      ("spoton_buzzpage::slotSendMessage(): write() failure.");
  else
    m_kernelSocket->flush();

  ui.message->clear();
}
