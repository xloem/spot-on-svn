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
				 const QByteArray &channel,
				 const QByteArray &id,
				 QWidget *parent):QWidget(parent)
{
  m_channel = channel;
  m_id = id;
  m_kernelSocket = kernelSocket;
  m_statusTimer.start(45000);
  ui.setupUi(this);
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimeout(void)));
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
  ui.clients->setColumnHidden(2, true); // Time
  ui.clients->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  ui.splitter->setStretchFactor(0, 1);
  ui.splitter->setStretchFactor(1, 0);
  slotSetIcons();
}

spoton_buzzpage::~spoton_buzzpage()
{
  m_messagingCache.clear();
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
  message.append(m_channel.toBase64());
  message.append("_");
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

void spoton_buzzpage::appendMessage(const QByteArray &hash,
				    const QList<QByteArray> &list)
{
  if(list.size() != 3)
    return;

  if(m_messagingCache.contains(hash))
    return;
  else
    m_messagingCache.insert(hash, 0);

  QByteArray id(list.at(1));
  QByteArray name(list.at(0));
  QByteArray message(list.at(2));
  QString msg("");

  if(name.isEmpty())
    name = "unknown";

  if(message.isEmpty())
    message = "unknown";

  msg.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  msg.append
    (QString("<font color=blue>%1: </font>").
     arg(QString::fromUtf8(name.constData(),
			   name.length())));
  msg.append(QString::fromUtf8(message.constData(),
			       message.length()));
  ui.messages->append(msg);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());
}

void spoton_buzzpage::slotSendStatus(void)
{
  if(!m_kernelSocket)
    return;
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray name;
  QByteArray message;
  QSettings settings;

  name = settings.value("gui/buzzName", "unknown").toByteArray().trimmed();

  if(name.isEmpty())
    name = "unknown";

  message.clear();
  message.append("buzz_");
  message.append(m_channel.toBase64());
  message.append("_");
  message.append(name.toBase64());
  message.append("_");
  message.append(m_id.toBase64());
  message.append('\n');

  if(m_kernelSocket->write(message.constData(),
			   message.length()) != message.length())
    spoton_misc::logError
      ("spoton_buzzpage::slotSendStatus(): write() failure.");
  else
    m_kernelSocket->flush();
}

bool spoton_buzzpage::userStatus(const QList<QByteArray> &list)
{
  if(list.size() != 2)
    return false;

  bool changed = false;

  QList<QTableWidgetItem *> items
    (ui.clients->findItems(list.at(1), Qt::MatchExactly));

  ui.clients->setSortingEnabled(false);

  if(items.isEmpty())
    {
      changed = true;
      ui.clients->setRowCount(ui.clients->rowCount() + 1);

      QTableWidgetItem *item = 0;

      item = new QTableWidgetItem(list.at(0).constData());
      ui.clients->setItem(ui.clients->rowCount() - 1, 0, item);
      item = new QTableWidgetItem(list.at(1).constData());
      ui.clients->setItem(ui.clients->rowCount() - 1, 1, item);
      item = new QTableWidgetItem
	(QDateTime::currentDateTime().toString(Qt::ISODate));
      ui.clients->setItem(ui.clients->rowCount() - 1, 2, item);

      QString msg("");

      msg.append
	(QDateTime::currentDateTime().
	 toString("[hh:mm<font color=grey>:ss</font>] "));
      msg.append(tr("<i>User %1 has joined %2.</i>").
		 arg(list.at(0).constData()).
		 arg(m_channel.constData()));
      ui.messages->append(msg);
      ui.messages->verticalScrollBar()->setValue
	(ui.messages->verticalScrollBar()->maximum());
    }
  else
    {
      QTableWidgetItem *item = ui.clients->item(items.at(0)->row(), 0);

      if(item)
	if(item->text() != list.at(0).constData())
	  {
	    changed = true;

	    QString msg("");

	    msg.append
	      (QDateTime::currentDateTime().
	       toString("[hh:mm<font color=grey>:ss</font>] "));
	    msg.append(tr("<i>%1 is now known as %2.</i>").
		       arg(item->text()).
		       arg(list.at(0).constData()));
	    ui.messages->append(msg);
	    ui.messages->verticalScrollBar()->setValue
	      (ui.messages->verticalScrollBar()->maximum());
	    item->setText(list.at(0).constData());
	  }
    }

  ui.clients->setSortingEnabled(true);
  ui.clients->resizeColumnToContents(0);
  ui.clients->horizontalHeader()->setStretchLastSection(true);
  return changed;
}

void spoton_buzzpage::slotStatusTimeout(void)
{
  QDateTime now(QDateTime::currentDateTime());

  for(int i = ui.clients->rowCount() - 1; i >= 0; i--)
    {
      QTableWidgetItem *item = ui.clients->item(i, 2);

      if(item)
	{
	  QDateTime dateTime
	    (QDateTime::fromString(item->text(), Qt::ISODate));

	  if(dateTime.secsTo(now) >= 30)
	    {
	      QTableWidgetItem *item = ui.clients->item(i, 0);

	      if(item)
		{
		  QString msg("");

		  msg.append
		    (QDateTime::currentDateTime().
		     toString("[hh:mm<font color=grey>:ss</font>] "));
		  msg.append(tr("<i>%1 has parted %2.</i>").
			     arg(item->text()).
			     arg(m_channel.constData()));
		  ui.messages->append(msg);
		  ui.messages->verticalScrollBar()->setValue
		    (ui.messages->verticalScrollBar()->maximum());
		}

	      ui.clients->removeRow(i);
	    }
	}
    }
}
