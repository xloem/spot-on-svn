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

#include <QSslKey>

#include "spot-on.h"
#include "spot-on-buzzpage.h"

void spoton::slotSendMessage(void)
{
  QDateTime now(QDateTime::currentDateTime());
  QModelIndexList list(m_ui.participants->selectionModel()->
		       selectedRows(1)); // OID
  QModelIndexList publicKeyHashes(m_ui.participants->selectionModel()->
				  selectedRows(3)); // public_key_hash
  QString error("");
  QString msg("");

  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    {
      error = tr("Not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket.isEncrypted())
    {
      error = tr("The connection to the kernel is not encrypted.");
      goto done_label;
    }
  else if(m_ui.message->toPlainText().trimmed().isEmpty())
    {
      error = tr("Please provide a real message.");
      goto done_label;
    }

  if(!m_ui.participants->selectionModel()->hasSelection())
    {
      /*
      ** We need at least one participant.
      */

      error = tr("Please select at least one participant.");
      goto done_label;
    }

  msg.append
    (QString("[%1:%2<font color=grey>:%3</font>] ").
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  msg.append(tr("<b>me:</b> "));
  msg.append(m_ui.message->toPlainText().trimmed());
  m_ui.messages->append(msg);
  m_ui.messages->verticalScrollBar()->setValue
    (m_ui.messages->verticalScrollBar()->maximum());

  while(!list.isEmpty())
    {
      QModelIndex index(list.takeFirst());
      QString publicKeyHash(publicKeyHashes.takeFirst().data().toString());
      QVariant data(index.data());

      if(!data.isNull() && data.isValid())
	{
	  QByteArray message;
	  QByteArray name(m_settings.value("gui/nodeName", "unknown").
			  toByteArray().trimmed());

	  if(name.isEmpty())
	    name = "unknown";

	  m_chatSequenceNumbers[data.toInt()] += 1;
	  message.append("message_");
	  message.append(QString("%1_").arg(data.toString()));
	  message.append(name.toBase64());
	  message.append("_");
	  message.append(m_ui.message->toPlainText().trimmed().toUtf8().
			 toBase64());
	  message.append("_");
	  message.append
	    (QByteArray::number(m_chatSequenceNumbers[data.toInt()]).
	     toBase64());
	  message.append("_");
	  message.append(QDateTime::currentDateTime().toUTC().
			 toString("hhmmss").toLatin1().toBase64());
	  message.append('\n');

	  QPointer<spoton_chatwindow> chat = m_chatWindows.value
	    (publicKeyHash);

	  if(chat)
	    chat->append(msg);

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    spoton_misc::logError
	      (QString("spoton::slotSendMessage(): write() failure for "
		       "%1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	  else
	    {
	      if(m_ui.status->currentIndex() != 2) // Offline
		m_ui.status->setCurrentIndex(3); // Online

	      m_chatInactivityTimer.start();
	      m_kernelSocket.flush();
	    }
	}
    }

  m_ui.message->clear();

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
}

void spoton::slotReceivedKernelMessage(void)
{
  m_kernelSocket.flush();
  m_kernelSocketData.append(m_kernelSocket.readAll());

  if(m_kernelSocketData.endsWith('\n'))
    {
      QList<QByteArray> list
	(m_kernelSocketData.mid(0, m_kernelSocketData.lastIndexOf('\n')).
	 split('\n'));

      m_kernelSocketData.remove(0, m_kernelSocketData.lastIndexOf('\n'));

      while(!list.isEmpty())
	{
	  QByteArray data(list.takeFirst());

	  if(data.startsWith("authentication_requested_"))
	    {
	      data.remove(0, qstrlen("authentication_requested_"));

	      if(!data.isEmpty())
		authenticationRequested(data);
	    }
	  else if(data.startsWith("buzz_"))
	    {
	      data.remove(0, qstrlen("buzz_"));

	      QList<QByteArray> list(data.split('_'));

	      if(list.size() != 2)
		continue;

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      QByteArray key(list.value(1));

	      /*
	      ** Find the channel!
	      */

	      spoton_buzzpage *page = 0;

	      for(int i = 0; i < m_ui.buzzTab->count(); i++)
		{
		  page = qobject_cast<spoton_buzzpage *>
		    (m_ui.buzzTab->widget(i));

		  if(!page)
		    continue;

		  if(key == page->key())
		    break;
		  else
		    page = 0;
		}

	      if(page)
		{
		  list = list.value(0).split('\n');
		  list.removeAt(0); // Message Type

		  for(int i = 0; i < list.size(); i++)
		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  if(list.size() == 2)
		    page->userStatus(list);
		  else if(list.size() == 3)
		    page->appendMessage(list);
		}
	    }
	  else if(data.startsWith("message_"))
	    {
	      data.remove(0, qstrlen("message_"));

	      if(!data.isEmpty())
		{
		  QList<QByteArray> list(data.split('_'));

		  if(list.size() != 5)
		    continue;

		  for(int i = 0; i < list.size(); i++)
		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  QByteArray hash(list.at(0)); /*
					       ** SHA-512 hash of the sender's
					       ** public key.
					       */
		  QByteArray name(list.value(1));
		  QByteArray message(list.value(2));
		  QByteArray sequenceNumber(list.value(3));
		  QByteArray utcDate(list.value(4));
		  QDateTime dateTime
		    (QDateTime::fromString(utcDate.constData(),
					   "hhmmss"));
		  QDateTime now(QDateTime::currentDateTime());
		  QString content(QString::fromUtf8(message.constData(),
						    message.length()));
		  QString msg("");
		  bool ok = true;

		  if(name.isEmpty())
		    name = "unknown";

		  if(message.isEmpty())
		    content = "unknown";

		  ok = true;
		  sequenceNumber.toULongLong(&ok);

		  if(!ok || sequenceNumber == "0")
		    sequenceNumber = "1";

		  msg.append
		    (QString("[%1:%2<font color=grey>:%3</font>]:").
		     arg(now.toString("hh")).
		     arg(now.toString("mm")).
		     arg(now.toString("ss")));

		  if(dateTime.isValid())
		    msg.append
		      (QString("[<font color=green>%1:%2:%3</font>]").
		       arg(dateTime.toString("hh")).
		       arg(dateTime.toString("mm")).
		       arg(dateTime.toString("ss")));
		  else
		    msg.append
		      ("[<font color=red>00:00:00</font>]");

		  quint64 previousSequenceNumber = 1;

		  if(m_receivedChatSequenceNumbers.contains(hash))
		    previousSequenceNumber =
		      m_receivedChatSequenceNumbers[hash];
		  else
		    previousSequenceNumber = sequenceNumber.toULongLong() - 1;

		  m_receivedChatSequenceNumbers[hash] =
		    sequenceNumber.toULongLong();

		  if(sequenceNumber.toULongLong() !=
		     previousSequenceNumber + 1)
		    msg.append(QString(":<font color=red>%1</font>: ").
			       arg(sequenceNumber.constData()));
		  else
		    msg.append(QString(":%1: ").
			       arg(sequenceNumber.constData()));

		  msg.append
		    (QString("<font color=blue>%1: </font>").
		     arg(QString::fromUtf8(name.constData(),
					   name.length())));

		  if(spoton_misc::isValidBuzzMagnet(content.toLatin1()))
		    {
		      QString str("");

		      str.prepend("<a href='");
		      str.append(content);
		      str.append("'>");
		      str.append(content);
		      str.append("</a>");
		      content = str;
		    }
		  else if(spoton_misc::
			  isValidStarBeamMagnet(content.toLatin1()))
		    {
		      QString str("");

		      str.prepend("<a href='");
		      str.append(content);
		      str.append("'>");
		      str.append(content);
		      str.append("</a>");
		      content = str;
		    }

		  msg.append(content);

		  if(m_chatWindows.contains(list.value(0).toBase64()))
		    {
		      QPointer<spoton_chatwindow> chat =
			m_chatWindows.value(list.value(0).toBase64());

		      if(chat)
			{
			  chat->append(msg);

			  if(chat->isVisible())
			    chat->activateWindow();
			}
		    }

		  m_ui.messages->append(msg);
		  m_ui.messages->verticalScrollBar()->setValue
		    (m_ui.messages->verticalScrollBar()->maximum());

		  if(m_ui.tab->currentIndex() != 1)
		    m_sb.chat->setVisible(true);
		}
	    }
	  else if(data == "newmail")
	    m_sb.email->setVisible(true);
	}
    }
  else if(m_kernelSocketData.length() > 50000)
    {
      m_kernelSocketData.clear();
      spoton_misc::logError
	(QString("spoton::slotReceivedKernelMessage(): "
		 "unable to detect an EOL in m_kernelSocketData for %1:%2. "
		 "The container is bloated! Purging.").
	 arg(m_kernelSocket.peerAddress().toString()).
	 arg(m_kernelSocket.peerPort()));
    }
}

void spoton::slotShareChatPublicKey(void)
{
  if(!m_crypts.value("chat", 0) ||
     !m_crypts.value("chat-signature", 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypts.value("chat")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("chat")->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("chat-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("chat-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/nodeName", "unknown").
		      toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid);
      message.append("_");
      message.append(QByteArray("chat").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append('\n');

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotShareChatPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotShareEmailPublicKey(void)
{
  if(!m_crypts.value("email", 0) ||
     !m_crypts.value("email-signature", 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypts.value("email")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("email")->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("email-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("email-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/emailName", "unknown").
		      toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid);
      message.append("_");
      message.append(QByteArray("email").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append('\n');

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotShareEmailPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotRemoveParticipants(void)
{
  if(!m_ui.participants->selectionModel()->hasSelection())
    return;

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"participant(s)?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QModelIndexList list
	  (m_ui.participants->selectionModel()->selectedRows(1)); // OID
	QModelIndexList listHashes
	  (m_ui.participants->selectionModel()->
	   selectedRows(3)); // public_key_hash
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());
	    QVariant hash(listHashes.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      {
		query.prepare("DELETE FROM friends_public_keys WHERE "
			      "OID = ?");
		query.bindValue(0, data.toString());
		query.exec();
	      }

	    if(m_chatSequenceNumbers.contains(data.toInt()))
	      m_chatSequenceNumbers.remove(data.toInt());

	    if(m_receivedChatSequenceNumbers.contains(hash.toByteArray()))
	      m_receivedChatSequenceNumbers.remove(hash.toByteArray());

	    if(m_chatWindows.contains(hash.toString()))
	      {
		QPointer<spoton_chatwindow> chat =
		  m_chatWindows.value(hash.toString());

		m_chatWindows.remove(hash.toString());

		if(chat)
		  chat->deleteLater();
	      }
	  }

	spoton_misc::purgeSignatureRelationships(db);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSaveBuzzName(void)
{
  QString str(m_ui.buzzName->text().trimmed());

  if(str.isEmpty())
    {
      str = "unknown";
      m_ui.buzzName->setText(str);
    }

  m_settings["gui/buzzName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/buzzName", str.toUtf8());
  m_ui.buzzName->selectAll();
  emit buzzNameChanged(str.toUtf8());
}

void spoton::slotSaveEmailName(void)
{
  QString str(m_ui.emailName->text().trimmed());

  if(str.isEmpty())
    {
      str = "unknown";
      m_ui.emailName->setText(str);
    }

  m_settings["gui/emailName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/emailName", str.toUtf8());
  m_ui.emailName->selectAll();
}

void spoton::slotSaveNodeName(void)
{
  QString str(m_ui.nodeName->text().trimmed());

  if(str.isEmpty())
    {
      str = "unknown";
      m_ui.nodeName->setText(str);
    }

  m_settings["gui/nodeName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/nodeName", str.toUtf8());
  m_ui.nodeName->selectAll();
}

void spoton::highlightPaths(void)
{
  QColor color;
  QFileInfo fileInfo;
  QPalette palette;

  fileInfo.setFile(m_ui.destination->text());

  if(fileInfo.isReadable() && fileInfo.isWritable())
    color = QColor(144, 238, 144);
  else
    color = QColor(240, 128, 128); // Light coral!

  palette.setColor(m_ui.destination->backgroundRole(), color);
  m_ui.destination->setPalette(palette);
#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  fileInfo.setFile(m_ui.geoipPath->text());

  if(fileInfo.isReadable() && fileInfo.size() > 0)
    color = QColor(144, 238, 144);
  else
    color = QColor(240, 128, 128); // Light coral!
#else
  color = QColor(240, 128, 128); // Light coral!
#endif

  palette.setColor(m_ui.geoipPath->backgroundRole(), color);
  m_ui.geoipPath->setPalette(palette);
  fileInfo.setFile(m_ui.kernelPath->text());

#if defined(Q_OS_MAC)
  if((fileInfo.isBundle() || fileInfo.isExecutable()) && fileInfo.size() > 0)
#elif defined(Q_OS_WIN32)
  if(fileInfo.isReadable() && fileInfo.size() > 0)
#else
  if(fileInfo.isExecutable() && fileInfo.size() > 0)
#endif
    color = QColor(144, 238, 144);
  else
    color = QColor(240, 128, 128); // Light coral!

  palette.setColor(m_ui.kernelPath->backgroundRole(), color);
  m_ui.kernelPath->setPalette(palette);
}

void spoton::slotAcceptPublicizedListeners(void)
{
  QRadioButton *radioButton = qobject_cast<QRadioButton *> (sender());

  if(!radioButton)
    return;

  if(m_ui.acceptPublishedConnected == radioButton)
    {
      m_settings["gui/acceptPublicizedListeners"] = "connected";
      m_ui.publishedKeySize->setEnabled(true);
    }
  else if(m_ui.acceptPublishedDisconnected == radioButton)
    {
      m_settings["gui/acceptPublicizedListeners"] = "disconnected";
      m_ui.publishedKeySize->setEnabled(true);
    }
  else
    {
      m_settings["gui/acceptPublicizedListeners"] = "ignored";
      m_ui.publishedKeySize->setEnabled(false);
    }

  QSettings settings;

  settings.setValue("gui/acceptPublicizedListeners",
		    m_settings.value("gui/acceptPublicizedListeners"));
}

void spoton::slotKeepOnlyUserDefinedNeighbors(bool state)
{
  m_settings["gui/keepOnlyUserDefinedNeighbors"] = state;

  QSettings settings;

  settings.setValue("gui/keepOnlyUserDefinedNeighbors", state);

  if(state)
    m_neighborsLastModificationTime = QDateTime();
}

void spoton::slotPublishPeriodicallyToggled(bool state)
{
  m_settings["gui/publishPeriodically"] = state;

  QSettings settings;

  settings.setValue("gui/publishPeriodically", state);
}

void spoton::prepareListenerIPCombo(void)
{
  m_ui.listenerIPCombo->clear();

  QList<QNetworkInterface> interfaces(QNetworkInterface::allInterfaces());
  QStringList list;

  while(!interfaces.isEmpty())
    {
      QNetworkInterface interface(interfaces.takeFirst());

      if(!interface.isValid() || !(interface.flags() &
				   QNetworkInterface::IsUp))
	continue;

      QList<QNetworkAddressEntry> addresses(interface.addressEntries());

      while(!addresses.isEmpty())
	{
	  QHostAddress address(addresses.takeFirst().ip());

	  if(m_ui.ipv4Listener->isChecked())
	    {
	      if(address.protocol() == QAbstractSocket::IPv4Protocol)
		list.append(address.toString());
	    }
	  else
	    {
	      if(address.protocol() == QAbstractSocket::IPv6Protocol)
		list.append(QHostAddress(address.toIPv6Address()).toString());
	    }
	}
    }

  if(!list.isEmpty())
    {
      qSort(list);
      m_ui.listenerIPCombo->addItem(tr("Custom"));
      m_ui.listenerIPCombo->insertSeparator(1);
      m_ui.listenerIPCombo->addItems(list);
    }
  else
    m_ui.listenerIPCombo->addItem(tr("Custom"));
}

void spoton::slotListenerIPComboChanged(int index)
{
  /*
  ** Method will be called because of activity in prepareListenerIPCombo().
  */

  if(index == 0)
    {
      m_ui.listenerIP->clear();
      m_ui.listenerScopeId->clear();
      m_ui.listenerIP->setEnabled(true);
    }
  else
    {
      m_ui.listenerIP->setText(m_ui.listenerIPCombo->currentText());
      m_ui.listenerIP->setEnabled(false);
    }
}

void spoton::slotChatSendMethodChanged(int index)
{
  if(index == 0)
    m_settings["gui/chatSendMethod"] = "Normal_POST";
  else
    m_settings["gui/chatSendMethod"] = "Artificial_GET";

  QSettings settings;

  settings.setValue
    ("gui/chatSendMethod",
     m_settings.value("gui/chatSendMethod").toString());
}

void spoton::slotShareChatPublicKeyWithParticipant(void)
{
  sharePublicKeyWithParticipant("chat");
}

void spoton::slotShareEmailPublicKeyWithParticipant(void)
{
  sharePublicKeyWithParticipant("email");
}

void spoton::slotShareUrlPublicKeyWithParticipant(void)
{
  sharePublicKeyWithParticipant("url");
}

void spoton::slotViewLog(void)
{
  m_logViewer.show(this);
}

void spoton::slotStatusChanged(int index)
{
  if(index == 0)
    m_settings["gui/my_status"] = "Away";
  else if(index == 1)
    m_settings["gui/my_status"] = "Busy";
  else if(index == 2)
    m_settings["gui/my_status"] = "Offline";
  else
    m_settings["gui/my_status"] = "Online";

  QSettings settings;

  settings.setValue
    ("gui/my_status", m_settings.value("gui/my_status"));
}

void spoton::slotKernelCipherTypeChanged(int index)
{
  if(index == 0)
    m_settings["gui/kernelCipherType"] = "randomized";
  else
    m_settings["gui/kernelCipherType"] =
      m_ui.kernelCipherType->currentText().toLower();

  QSettings settings;

  settings.setValue
    ("gui/kernelCipherType", m_settings.value("gui/kernelCipherType"));
}

bool spoton::isKernelActive(void) const
{
  return m_ui.pid->text().toInt() > 0;
}

void spoton::slotCopyMyChatPublicKey(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyChatPublicKey());
}

QByteArray spoton::copyMyChatPublicKey(void) const
{
  if(!m_crypts.value("chat", 0) ||
     !m_crypts.value("chat-signature", 0))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  bool ok = true;

  name = m_settings.value("gui/nodeName", "unknown").toByteArray().
    trimmed();
  mPublicKey = m_crypts.value("chat")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("chat")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("chat-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("chat-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("chat").toBase64() + "@" +
      name.toBase64() + "@" +
      mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QPixmap spoton::pixmapForCountry(const QString &country) const
{
  if(country == "Afghanistan")
    return QPixmap(":/Flags/af.png");
  else if(country == "Albania")
    return QPixmap(":/Flags/al.png");
  else if(country == "Algeria")
    return QPixmap(":/Flags/dz.png");
  else if(country == "AmericanSamoa")
    return QPixmap(":/Flags/as.png");
  else if(country == "Angola")
    return QPixmap(":/Flags/ao.png");
  else if(country == "Argentina")
    return QPixmap(":/Flags/ar.png");
  else if(country == "Armenia")
    return QPixmap(":/Flags/am.png");
  else if(country == "Aruba")
    return QPixmap(":/Flags/aw.png");
  else if(country == "Australia")
    return QPixmap(":/Flags/au.png");
  else if(country == "Austria")
    return QPixmap(":/Flags/at.png");
  else if(country == "Azerbaijan")
    return QPixmap(":/Flags/az.png");
  else if(country == "Bahrain")
    return QPixmap(":/Flags/bh.png");
  else if(country == "Bangladesh")
    return QPixmap(":/Flags/bd.png");
  else if(country == "Barbados")
    return QPixmap(":/Flags/bb.png");
  else if(country == "Belarus")
    return QPixmap(":/Flags/by.png");
  else if(country == "Belgium")
    return QPixmap(":/Flags/be.png");
  else if(country == "Belize")
    return QPixmap(":/Flags/bz.png");
  else if(country == "Benin")
    return QPixmap(":/Flags/bj.png");
  else if(country == "Bermuda")
    return QPixmap(":/Flags/bm.png");
  else if(country == "Bhutan")
    return QPixmap(":/Flags/bt.png");
  else if(country == "Bolivia")
    return QPixmap(":/Flags/bo.png");
  else if(country == "BosniaAndHerzegowina")
    return QPixmap(":/Flags/ba.png");
  else if(country == "Botswana")
    return QPixmap(":/Flags/bw.png");
  else if(country == "Brazil")
    return QPixmap(":/Flags/br.png");
  else if(country == "BruneiDarussalam")
    return QPixmap(":/Flags/bn.png");
  else if(country == "Bulgaria")
    return QPixmap(":/Flags/bg.png");
  else if(country == "BurkinaFaso")
    return QPixmap(":/Flags/bf.png");
  else if(country == "Burundi")
    return QPixmap(":/Flags/bi.png");
  else if(country == "Cambodia")
    return QPixmap(":/Flags/kh.png");
  else if(country == "Cameroon")
    return QPixmap(":/Flags/cm.png");
  else if(country == "Canada")
    return QPixmap(":/Flags/ca.png");
  else if(country == "CapeVerde")
    return QPixmap(":/Flags/cv.png");
  else if(country == "CentralAfricanRepublic")
    return QPixmap(":/Flags/cf.png");
  else if(country == "Chad")
    return QPixmap(":/Flags/td.png");
  else if(country == "Chile")
    return QPixmap(":/Flags/cl.png");
  else if(country == "China")
    return QPixmap(":/Flags/cn.png");
  else if(country == "Colombia")
    return QPixmap(":/Flags/co.png");
  else if(country == "Comoros")
    return QPixmap(":/Flags/km.png");
  else if(country == "CostaRica")
    return QPixmap(":/Flags/cr.png");
  else if(country == "Croatia")
    return QPixmap(":/Flags/hr.png");
  else if(country == "Cyprus")
    return QPixmap(":/Flags/cy.png");
  else if(country == "CzechRepublic")
    return QPixmap(":/Flags/cz.png");
  else if(country == "Default")
    return QPixmap(":/Flags/us.png");
  else if(country == "DemocraticRepublicOfCongo")
    return QPixmap(":/Flags/cd.png");
  else if(country == "Denmark")
    return QPixmap(":/Flags/dk.png");
  else if(country == "Djibouti")
    return QPixmap(":/Flags/dj.png");
  else if(country == "DominicanRepublic")
    return QPixmap(":/Flags/do.png");
  else if(country == "Ecuador")
    return QPixmap(":/Flags/ec.png");
  else if(country == "Egypt")
    return QPixmap(":/Flags/eg.png");
  else if(country == "ElSalvador")
    return QPixmap(":/Flags/sv.png");
  else if(country == "EquatorialGuinea")
    return QPixmap(":/Flags/gq.png");
  else if(country == "Eritrea")
    return QPixmap(":/Flags/er.png");
  else if(country == "Estonia")
    return QPixmap(":/Flags/ee.png");
  else if(country == "Ethiopia")
    return QPixmap(":/Flags/et.png");
  else if(country == "FaroeIslands")
    return QPixmap(":/Flags/fo.png");
  else if(country == "Finland")
    return QPixmap(":/Flags/fi.png");
  else if(country == "France")
    return QPixmap(":/Flags/fr.png");
  else if(country == "FrenchGuiana")
    return QPixmap(":/Flags/gy.png");
  else if(country == "Gabon")
    return QPixmap(":/Flags/ga.png");
  else if(country == "Georgia")
    return QPixmap(":/Flags/ge.png");
  else if(country == "Germany")
    return QPixmap(":/Flags/de.png");
  else if(country == "Ghana")
    return QPixmap(":/Flags/gh.png");
  else if(country == "Greece")
    return QPixmap(":/Flags/gr.png");
  else if(country == "Greenland")
    return QPixmap(":/Flags/gl.png");
  else if(country == "Guadeloupe")
    return QPixmap(":/Flags/fr.png");
  else if(country == "Guam")
    return QPixmap(":/Flags/gu.png");
  else if(country == "Guatemala")
    return QPixmap(":/Flags/gt.png");
  else if(country == "Guinea")
    return QPixmap(":/Flags/gn.png");
  else if(country == "GuineaBissau")
    return QPixmap(":/Flags/gw.png");
  else if(country == "Guyana")
    return QPixmap(":/Flags/gy.png");
  else if(country == "Honduras")
    return QPixmap(":/Flags/hn.png");
  else if(country == "HongKong")
    return QPixmap(":/Flags/hk.png");
  else if(country == "Hungary")
    return QPixmap(":/Flags/hu.png");
  else if(country == "Iceland")
    return QPixmap(":/Flags/is.png");
  else if(country == "India")
    return QPixmap(":/Flags/in.png");
  else if(country == "Indonesia")
    return QPixmap(":/Flags/id.png");
  else if(country == "Iran")
    return QPixmap(":/Flags/ir.png");
  else if(country == "Iraq")
    return QPixmap(":/Flags/iq.png");
  else if(country == "Ireland")
    return QPixmap(":/Flags/ie.png");
  else if(country == "Israel")
    return QPixmap(":/Flags/il.png");
  else if(country == "Italy")
    return QPixmap(":/Flags/it.png");
  else if(country == "IvoryCoast")
    return QPixmap(":/Flags/ci.png");
  else if(country == "Jamaica")
    return QPixmap(":/Flags/jm.png");
  else if(country == "Japan")
    return QPixmap(":/Flags/jp.png");
  else if(country == "Jordan")
    return QPixmap(":/Flags/jo.png");
  else if(country == "Kazakhstan")
    return QPixmap(":/Flags/kz.png");
  else if(country == "Kenya")
    return QPixmap(":/Flags/ke.png");
  else if(country == "Kuwait")
    return QPixmap(":/Flags/kw.png");
  else if(country == "Kyrgyzstan")
    return QPixmap(":/Flags/kg.png");
  else if(country == "Lao")
    return QPixmap(":/Flags/la.png");
  else if(country == "LatinAmericaAndTheCaribbean")
    return QPixmap(":/Flags/mx.png");
  else if(country == "Latvia")
    return QPixmap(":/Flags/lv.png");
  else if(country == "Lebanon")
    return QPixmap(":/Flags/lb.png");
  else if(country == "Lesotho")
    return QPixmap(":/Flags/ls.png");
  else if(country == "Liberia")
    return QPixmap(":/Flags/lr.png");
  else if(country == "LibyanArabJamahiriya")
    return QPixmap(":/Flags/ly.png");
  else if(country == "Liechtenstein")
    return QPixmap(":/Flags/li.png");
  else if(country == "Lithuania")
    return QPixmap(":/Flags/lt.png");
  else if(country == "Luxembourg")
    return QPixmap(":/Flags/lu.png");
  else if(country == "Macau")
    return QPixmap(":/Flags/mo.png");
  else if(country == "Macedonia")
    return QPixmap(":/Flags/mk.png");
  else if(country == "Madagascar")
    return QPixmap(":/Flags/mg.png");
  else if(country == "Malaysia")
    return QPixmap(":/Flags/my.png");
  else if(country == "Mali")
    return QPixmap(":/Flags/ml.png");
  else if(country == "Malta")
    return QPixmap(":/Flags/mt.png");
  else if(country == "MarshallIslands")
    return QPixmap(":/Flags/mh.png");
  else if(country == "Martinique")
    return QPixmap(":/Flags/fr.png");
  else if(country == "Mauritius")
    return QPixmap(":/Flags/mu.png");
  else if(country == "Mayotte")
    return QPixmap(":/Flags/yt.png");
  else if(country == "Mexico")
    return QPixmap(":/Flags/mx.png");
  else if(country == "Moldova")
    return QPixmap(":/Flags/md.png");
  else if(country == "Monaco")
    return QPixmap(":/Flags/mc.png");
  else if(country == "Mongolia")
    return QPixmap(":/Flags/mn.png");
  else if(country == "Montenegro")
    return QPixmap(":/Flags/me.png");
  else if(country == "Morocco")
    return QPixmap(":/Flags/ma.png");
  else if(country == "Mozambique")
    return QPixmap(":/Flags/mz.png");
  else if(country == "Myanmar")
    return QPixmap(":/Flags/mm.png");
  else if(country == "Namibia")
    return QPixmap(":/Flags/na.png");
  else if(country == "Nepal")
    return QPixmap(":/Flags/np.png");
  else if(country == "Netherlands")
    return QPixmap(":/Flags/nl.png");
  else if(country == "NewZealand")
    return QPixmap(":/Flags/nz.png");
  else if(country == "Nicaragua")
    return QPixmap(":/Flags/ni.png");
  else if(country == "Niger")
    return QPixmap(":/Flags/ne.png");
  else if(country == "Nigeria")
    return QPixmap(":/Flags/ng.png");
  else if(country == "NorthernMarianaIslands")
    return QPixmap(":/Flags/mp.png");
  else if(country == "Norway")
    return QPixmap(":/Flags/no.png");
  else if(country == "Oman")
    return QPixmap(":/Flags/om.png");
  else if(country == "Pakistan")
    return QPixmap(":/Flags/pk.png");
  else if(country == "Panama")
    return QPixmap(":/Flags/pa.png");
  else if(country == "Paraguay")
    return QPixmap(":/Flags/py.png");
  else if(country == "PeoplesRepublicOfCongo")
    return QPixmap(":/Flags/cg.png");
  else if(country == "Peru")
    return QPixmap(":/Flags/pe.png");
  else if(country == "Philippines")
    return QPixmap(":/Flags/ph.png");
  else if(country == "Poland")
    return QPixmap(":/Flags/pl.png");
  else if(country == "Portugal")
    return QPixmap(":/Flags/pt.png");
  else if(country == "PuertoRico")
    return QPixmap(":/Flags/pr.png");
  else if(country == "Qatar")
    return QPixmap(":/Flags/qa.png");
  else if(country == "RepublicOfKorea")
    return QPixmap(":/Flags/kr.png");
  else if(country == "Reunion")
    return QPixmap(":/Flags/fr.png");
  else if(country == "Romania")
    return QPixmap(":/Flags/ro.png");
  else if(country == "RussianFederation")
    return QPixmap(":/Flags/ru.png");
  else if(country == "Rwanda")
    return QPixmap(":/Flags/rw.png");
  else if(country == "Saint Barthelemy")
    return QPixmap(":/Flags/bl.png");
  else if(country == "Saint Martin")
    return QPixmap(":/Flags/fr.png");
  else if(country == "SaoTomeAndPrincipe")
    return QPixmap(":/Flags/st.png");
  else if(country == "SaudiArabia")
    return QPixmap(":/Flags/sa.png");
  else if(country == "Senegal")
    return QPixmap(":/Flags/sn.png");
  else if(country == "Serbia")
    return QPixmap(":/Flags/rs.png");
  else if(country == "SerbiaAndMontenegro")
    return QPixmap(":/Flags/rs.png");
  else if(country == "Singapore")
    return QPixmap(":/Flags/sg.png");
  else if(country == "Slovakia")
    return QPixmap(":/Flags/sk.png");
  else if(country == "Slovenia")
    return QPixmap(":/Flags/si.png");
  else if(country == "Somalia")
    return QPixmap(":/Flags/so.png");
  else if(country == "SouthAfrica")
    return QPixmap(":/Flags/za.png");
  else if(country == "Spain")
    return QPixmap(":/Flags/es.png");
  else if(country == "SriLanka")
    return QPixmap(":/Flags/lk.png");
  else if(country == "Sudan")
    return QPixmap(":/Flags/sd.png");
  else if(country == "Swaziland")
    return QPixmap(":/Flags/sz.png");
  else if(country == "Sweden")
    return QPixmap(":/Flags/se.png");
  else if(country == "Switzerland")
    return QPixmap(":/Flags/ch.png");
  else if(country == "SyrianArabRepublic")
    return QPixmap(":/Flags/sy.png");
  else if(country == "Taiwan")
    return QPixmap(":/Flags/tw.png");
  else if(country == "Tajikistan")
    return QPixmap(":/Flags/tj.png");
  else if(country == "Tanzania")
    return QPixmap(":/Flags/tz.png");
  else if(country == "Thailand")
    return QPixmap(":/Flags/th.png");
  else if(country == "Togo")
    return QPixmap(":/Flags/tg.png");
  else if(country == "Tonga")
    return QPixmap(":/Flags/to.png");
  else if(country == "TrinidadAndTobago")
    return QPixmap(":/Flags/tt.png");
  else if(country == "Tunisia")
    return QPixmap(":/Flags/tn.png");
  else if(country == "Turkey")
    return QPixmap(":/Flags/tr.png");
  else if(country == "USVirginIslands")
    return QPixmap(":/Flags/vi.png");
  else if(country == "Uganda")
    return QPixmap(":/Flags/ug.png");
  else if(country == "Ukraine")
    return QPixmap(":/Flags/ua.png");
  else if(country == "UnitedArabEmirates")
    return QPixmap(":/Flags/ae.png");
  else if(country == "UnitedKingdom")
    return QPixmap(":/Flags/gb.png");
  else if(country == "UnitedStates")
    return QPixmap(":/Flags/us.png");
  else if(country == "UnitedStatesMinorOutlyingIslands")
    return QPixmap(":/Flags/us.png");
  else if(country == "Uruguay")
    return QPixmap(":/Flags/uy.png");
  else if(country == "Uzbekistan")
    return QPixmap(":/Flags/uz.png");
  else if(country == "Venezuela")
    return QPixmap(":/Flags/ve.png");
  else if(country == "VietNam")
    return QPixmap(":/Flags/vn.png");
  else if(country == "Yemen")
    return QPixmap(":/Flags/ye.png");
  else if(country == "Yugoslavia")
    return QPixmap(":/Flags/yu.png");
  else if(country == "Zambia")
    return QPixmap(":/Flags/zm.png");
  else if(country == "Zimbabwe")
    return QPixmap(":/Flags/zw.png");
  else
    return QPixmap(":/Flags/unknown.png");
}

void spoton::slotAddBootstrapper(void)
{
}

void spoton::slotFetchMoreAlgo(void)
{
}

void spoton::slotFetchMoreButton(void)
{
}

void spoton::slotAddFriendsKey(void)
{
  QByteArray key
    (m_ui.friendInformation->toPlainText().trimmed().toLatin1());

  if(key.startsWith("K") || key.startsWith("k"))
    {
      QList<QByteArray> list(key.split('@'));

      while(!list.isEmpty())
	if(list.size() >= 6)
	  {
	    QByteArray bytes("K");

	    bytes.append(list.takeFirst().remove(0, 1));
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    addFriendsKey(bytes);
	  }
	else
	  break;
    }
  else
    addFriendsKey(key);
}

void spoton::addFriendsKey(const QByteArray &key)
{
  if(m_ui.addFriendPublicKeyRadio->isChecked())
    {
      if(!m_crypts.value("chat", 0) ||
	 !m_crypts.value("email", 0) ||
	 !m_crypts.value("rosetta", 0) ||
	 !m_crypts.value("url", 0))
	{
	  QMessageBox::critical(this, tr("Spot-On: Error"),
				tr("Invalid spoton_crypt object(s). This is "
				   "a fatal flaw."));
	  return;
	}
      else if(key.trimmed().isEmpty())
	{
	  QMessageBox::critical(this, tr("Spot-On: Error"),
				tr("Empty key. Really?"));
	  return;
	}

      if(!(key.startsWith("K") || key.startsWith("k")))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid key. The key must start with either the letter "
		"K or the letter k."));
	  return;
	}

      QList<QByteArray> list(key.mid(1).split('@'));

      if(list.size() != 6)
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Irregular data. Expecting 6 entries, received %1.").
	     arg(list.size()));
	  return;
	}

      QByteArray keyType(list.value(0));

      keyType = QByteArray::fromBase64(keyType);

      if(!(keyType == "chat" || keyType == "email" ||
	   keyType == "rosetta" || keyType == "url"))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid key type. Expecting 'chat', 'email', 'rosetta', "
		"or 'url'."));
	  return;
	}

      QByteArray mPublicKey(list.value(2));
      QByteArray mSignature(list.value(3));
      QByteArray myPublicKey;
      QByteArray mySPublicKey;
      bool ok = true;

      mPublicKey = QByteArray::fromBase64(mPublicKey);
      myPublicKey = m_crypts.value(keyType)->publicKey(&ok);

      if(!ok)
	{
	  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	  mb.setIcon(QMessageBox::Question);
	  mb.setWindowTitle(tr("Spot-On: Confirmation"));
	  mb.setWindowModality(Qt::WindowModal);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Unable to retrieve your %1 "
			"public key for comparison. Continue?").
		     arg(keyType.constData()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      mySPublicKey = m_crypts.value
	(QString("%1-signature").arg(keyType.constData()))->publicKey(&ok);

      if(!ok)
	{
	  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	  mb.setIcon(QMessageBox::Question);
	  mb.setWindowTitle(tr("Spot-On: Confirmation"));
	  mb.setWindowModality(Qt::WindowModal);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Unable to retrieve your %1 signature "
			"public key for comparison. Continue?").
		     arg(keyType.constData()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      if(mPublicKey == myPublicKey || mSignature == mySPublicKey)
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("You're attempting to add your own '%1' keys. "
		"Please do not do this!").arg(keyType.constData()));
	  return;
	}

      mSignature = QByteArray::fromBase64(mSignature);

      if(!spoton_crypt::isValidSignature(mPublicKey, mPublicKey,
					 mSignature))
	{
	  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	  mb.setIcon(QMessageBox::Question);
	  mb.setWindowTitle(tr("Spot-On: Confirmation"));
	  mb.setWindowModality(Qt::WindowModal);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Invalid 'chat', 'email', 'rosetta', or 'url' "
			"public key signature. Accept?"));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      QByteArray sPublicKey(list.value(4));
      QByteArray sSignature(list.value(5));

      sPublicKey = QByteArray::fromBase64(sPublicKey);
      sSignature = QByteArray::fromBase64(sSignature);

      if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey,
					 sSignature))
	{
	  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	  mb.setIcon(QMessageBox::Question);
	  mb.setWindowTitle(tr("Spot-On: Confirmation"));
	  mb.setWindowModality(Qt::WindowModal);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Invalid signature "
			"public key signature. Accept?"));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    QByteArray name(list.value(1));

	    name = QByteArray::fromBase64(name);

	    if(spoton_misc::saveFriendshipBundle(keyType,
						 name,
						 mPublicKey,
						 sPublicKey,
						 -1,
						 db))
	      if(spoton_misc::saveFriendshipBundle(keyType + "-signature",
						   name,
						   sPublicKey,
						   QByteArray(),
						   -1,
						   db))
		m_ui.friendInformation->selectAll();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
  else
    {
      /*
      ** Now we have to perform the inverse of slotCopyFriendshipBundle().
      ** Have fun!
      */

      if(!m_crypts.value("chat", 0) ||
	 !m_crypts.value("email", 0) ||
	 !m_crypts.value("rosetta", 0) ||
	 !m_crypts.value("url", 0))
	{
	  QMessageBox::critical(this, tr("Spot-On: Error"),
				tr("Invalid spoton_crypt object(s). This is "
				   "a fatal flaw."));
	  return;
	}
      else if(key.trimmed().isEmpty())
	{
	  QMessageBox::critical(this, tr("Spot-On: Error"),
				tr("Empty key. Really?"));
	  return;
	}

      if(!(key.startsWith("R") || key.startsWith("r")))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid repleo. The repleo must start with "
		"either the letter R or the letter r."));
	  return;
	}

      QList<QByteArray> list(key.mid(1).split('@'));

      if(list.size() != 3)
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Irregular data. Expecting 3 entries, received %1.").
	     arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray data(list.value(1));
      QByteArray hash(list.value(2));
      QByteArray keyInformation(list.value(0));
      bool ok = true;

      keyInformation = m_crypts.value("chat")->
	publicKeyDecrypt(list.value(0), &ok);

      if(!ok)
	{
	  keyInformation = m_crypts.value("email")->
	    publicKeyDecrypt(list.value(0), &ok);

	  if(!ok)
	    {
	      keyInformation = m_crypts.value("rosetta")->
		publicKeyDecrypt(list.value(0), &ok);

	      if(!ok)
		{
		  keyInformation = m_crypts.value("url")->
		    publicKeyDecrypt(list.value(0), &ok);

		  if(!ok)
		    {
		      QMessageBox::critical
			(this, tr("Spot-On: Error"),
			 tr("Asymmetric decryption failure. "
			    "Are you attempting "
			    "to add a repleo that you gathered?"));
		      return;
		    }
		}
	    }
	}

      list = keyInformation.split('@');

      if(list.size() != 3)
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Irregular data. Expecting 3 entries, received %1.").
	     arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray computedHash;
      spoton_crypt crypt(list.value(1), // Cipher Type
			 QString("sha512"),
			 QByteArray(),
			 list.value(0), // Symmetric Key
			 0,
			 0,
			 QString(""));

      computedHash = spoton_crypt::keyedHash
	(data, list.value(2), "sha512", &ok);

      if(!ok)
	{
	  QMessageBox::critical(this, tr("Spot-On: Error"),
				tr("Unable to compute a keyed hash."));
	  return;
	}

      if(computedHash.isEmpty() || hash.isEmpty() ||
	 !spoton_crypt::memcmp(computedHash, hash))
	{
	  QMessageBox::critical(this, tr("Spot-On: Error"),
				tr("The computed hash does not match "
				   "the provided hash."));
	  return;
	}

      data = crypt.decrypted(data, &ok);

      if(!ok)
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Symmetric decryption failure. Serious!"));
	  return;
	}

      list = data.split('@');

      if(list.size() != 6)
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Irregular data. Expecting 6 entries, received %1.").
	     arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(!(list.value(0) == "chat" ||
	   list.value(0) == "email" ||
	   list.value(0) == "rosetta" ||
	   list.value(0) == "url"))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid key type. Expecting 'chat', 'email', 'rosetta', "
		"or 'url'."));
	  return;
	}

      for(int i = 1; i <= 4; i++)
	{
	  QByteArray myPublicKey;
	  QByteArray mySPublicKey;
	  bool ok = true;

	  if(i == 1)
	    {
	      myPublicKey = m_crypts.value("chat")->publicKey(&ok);

	      if(ok)
		mySPublicKey = m_crypts.value("chat-signature")->
		  publicKey(&ok);
	    }
	  else if(i == 2)
	    {
	      myPublicKey = m_crypts.value("email")->publicKey(&ok);

	      if(ok)
		mySPublicKey = m_crypts.value("email-signature")->
		  publicKey(&ok);
	    }
	  else if(i == 3)
	    {
	      myPublicKey = m_crypts.value("rosetta")->publicKey(&ok);

	      if(ok)
		mySPublicKey = m_crypts.value("rosetta-signature")->
		  publicKey(&ok);
	    }
	  else if(i == 4)
	    {
	      myPublicKey = m_crypts.value("url")->publicKey(&ok);

	      if(ok)
		mySPublicKey = m_crypts.value("url-signature")->
		  publicKey(&ok);
	    }

	  if(ok)
	    if(list.value(2) == myPublicKey ||
	       list.value(4) == mySPublicKey)
	      ok = false;

	  if(!ok)
	    {
	      QMessageBox::critical
		(this, tr("Spot-On: Error"),
		 tr("You're attempting to add your own keys or "
		    "Spot-On was not able to retrieve your keys for "
		    "comparison."));
	      return;
	    }
	}

      if(!spoton_crypt::isValidSignature(list.value(2),  // Data
					 list.value(2),  // Public Key
					 list.value(3))) // Signature
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid public key signature."));
	  return;
	}

      if(!spoton_crypt::
	 isValidSignature(list.value(4),  // Data
			  list.value(4),  // Signature Public Key
			  list.value(5))) // Signature
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid signature public key signature."));
	  return;
	}

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    if(spoton_misc::saveFriendshipBundle(list.value(0), // Key Type
						 list.value(1), // Name
						 list.value(2), // Public Key
						 list.value(4), // Signature
                                                                // Public Key
						 -1,            // Neighbor OID
						 db))
	      if(spoton_misc::
		 saveFriendshipBundle(list.value(0) + "-signature",
				      list.value(1), // Name
				      list.value(4), // Signature Public Key
				      QByteArray(),  // Signature Public Key
				      -1,            // Neighbor OID
				      db))
		m_ui.friendInformation->selectAll();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotDoSearch(void)
{
}

void spoton::slotDisplayLocalSearchResults(void)
{
}

void spoton::slotClearOutgoingMessage(void)
{
  if(m_ui.mailTab->currentIndex() == 1)
    {
      m_ui.emailParticipants->selectionModel()->clear();
      m_ui.outgoingMessage->clear();
      m_ui.outgoingMessage->setCurrentCharFormat(QTextCharFormat());
      m_ui.outgoingSubject->clear();
      m_ui.goldbug->clear();
      m_ui.outgoingSubject->setFocus();
    }
}

void spoton::slotResetAll(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to reset Spot-On? All "
		"data will be lost. Forever."));

  if(mb.exec() != QMessageBox::Yes)
    return;

  slotDeactivateKernel();

  QStringList list;

  list << "buzz_channels.db"
       << "email.db"
       << "error_log.dat"
       << "friends_public_keys.db"
       << "idiotes.db"
       << "kernel.db"
       << "listeners.db"
       << "neighbors.db"
       << "shared.db"
       << "starbeam.db";

  while(!list.isEmpty())
    QFile::remove
      (spoton_misc::homePath() + QDir::separator() + list.takeFirst());

  /*
  ** Remove the URL databases.
  */

  for(int i = 0; i < 26; i++)
    for(int j = 0; j < 26; j++)
      list.append(QString("urls_%1%2.db").
		  arg(static_cast<char> (i + 97)).
		  arg(static_cast<char> (j + 97)));

  while(!list.isEmpty())
    QFile::remove
      (spoton_misc::homePath() + QDir::separator() +
       "URLs" + QDir::separator() + list.takeFirst());

  QDir dir(spoton_misc::homePath());

  dir.rmdir("URLs");

  QSettings settings;

  for(int i = settings.allKeys().size() - 1; i >= 0; i--)
    settings.remove(settings.allKeys().at(i));

  QApplication::instance()->exit(0);

#ifdef Q_OS_WIN32
  QString program(QCoreApplication::applicationDirPath() +
		  QDir::separator() +
		  QCoreApplication::applicationName());

  int rc = (int)
    (::ShellExecuteA(0, "open", program.toUtf8().constData(),
		     0, 0, SW_SHOWNORMAL));

  if(rc == SE_ERR_ACCESSDENIED)
    /*
    ** Elevated?
    */

    ::ShellExecuteA(0, "runas", program.toUtf8().constData(),
		    0, 0, SW_SHOWNORMAL);
#else
  QProcess::startDetached(QCoreApplication::applicationDirPath() +
			  QDir::separator() +
			  QCoreApplication::applicationName());
#endif
}

void spoton::slotCopyFriendshipBundle(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  if(!m_crypts.value("chat", 0) ||
     !m_crypts.value("chat-signature", 0))
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item
	(row, 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      return;
    }

  /*
  ** 1. Generate some symmetric information, S.
  ** 2. Encrypt S with the participant's public key.
  ** 3. Encrypt our information (name, public keys, signatures) with the
  **    symmetric key. Call our information T.
  ** 4. Compute a keyed hash of T.
  */

  QString neighborOid("");
  QByteArray cipherType(m_settings.value("gui/kernelCipherType",
					 "randomized").
			toString().toLatin1());
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray symmetricKey;
  QPair<QByteArray, QByteArray> gemini;
  bool ok = true;

  if(cipherType == "randomized")
    cipherType = spoton_crypt::randomCipherType();

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     neighborOid,
				     cipherType,
				     oid,
				     m_crypts.value("chat", 0),
				     &ok);

  if(!ok || publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      return;
    }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" +
     cipherType.toBase64() + "@" +
     hashKey.toBase64(),
     publicKey, &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySPublicKey(m_crypts.value("chat-signature")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySSignature
    (m_crypts.value("chat-signature")->digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myPublicKey(m_crypts.value("chat")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySignature(m_crypts.value("chat")->
			 digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myName
    (m_settings.value("gui/nodeName", "unknown").toByteArray().
     trimmed());

  if(myName.isEmpty())
    myName = "unknown";

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     QString("sha512"),
		     QByteArray(),
		     symmetricKey,
		     0,
		     0,
		     QString(""));

  data = crypt.encrypted(QByteArray("chat").toBase64() + "@" +
			 myName.toBase64() + "@" +
			 myPublicKey.toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray hash(spoton_crypt::keyedHash(data, hashKey, "sha512", &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText("R" +
		     keyInformation.toBase64() + "@" +
		     data.toBase64() + "@" +
		     hash.toBase64());
}

Ui_spoton_mainwindow spoton::ui(void) const
{
  return m_ui;
}

void spoton::slotSendMail(void)
{
  if(!m_crypts.value("email", 0))
    return;

  /*
  ** Why would you send an empty message?
  */

  if(!m_ui.emailParticipants->selectionModel()->hasSelection())
    {
      QMessageBox::critical
	(this, tr("Spot-On: Error"),
	 tr("Please select at least one participant."));
      m_ui.emailParticipants->setFocus();
      return;
    }
  else if(m_ui.outgoingMessage->toPlainText().trimmed().isEmpty())
    {
      QMessageBox::critical
	(this, tr("Spot-On: Error"),
	 tr("Please compose an actual letter."));
      m_ui.outgoingMessage->setFocus();
      return;
    }

  QByteArray message
    (m_ui.outgoingMessage->toHtml().trimmed().toUtf8());

  /*
  ** Bundle the love letter and send it to the email.db file. The
  ** kernel shall do the rest.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QModelIndexList list;
	QStringList names;
	QStringList oids;
	QStringList publicKeyHashes;

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(0); // Participant

	while(!list.isEmpty())
	  names.append(list.takeFirst().data().toString());

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(1); // OID

	while(!list.isEmpty())
	  oids.append(list.takeFirst().data().toString());

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(3); // public_key_hash

	while(!list.isEmpty())
	  publicKeyHashes.append(list.takeFirst().data().toString());

	while(!oids.isEmpty())
	  {
	    QByteArray goldbug
	      (m_ui.goldbug->text().trimmed().toLatin1());
	    QByteArray publicKeyHash(publicKeyHashes.takeFirst().toLatin1());
	    QByteArray subject
	      (m_ui.outgoingSubject->text().trimmed().toUtf8());
	    QDateTime now(QDateTime::currentDateTime());
	    QSqlQuery query(db);
	    QString oid(oids.takeFirst());
	    bool ok = true;

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, goldbug, hash, "
			  "message, message_code, "
			  "receiver_sender, receiver_sender_hash, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, m_crypts.value("email")->
	       encrypted(now.toString(Qt::ISODate).
			 toLatin1(), &ok).toBase64());
	    query.bindValue(1, 1); // Sent Folder

	    if(ok)
	      query.bindValue
		(2, m_crypts.value("email")->
		 encrypted(goldbug, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, m_crypts.value("email")->
		 keyedHash(now.toString().toLatin1() +
			   message + subject, &ok).toBase64());

	    if(ok)
	      query.bindValue(4, m_crypts.value("email")->
			      encrypted(message, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5, m_crypts.value("email")->
		 encrypted(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(6, m_crypts.value("email")->
		 encrypted(names.takeFirst().toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(7, publicKeyHash.toBase64());

	    if(ok)
	      query.bindValue
		(8, m_crypts.value("email")->
		 encrypted(tr("Queued").toUtf8(),
			   &ok).toBase64());

	    if(ok)
	      query.bindValue
		(9, m_crypts.value("email")->
		 encrypted(subject, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(10, m_crypts.value("email")->encrypted(oid.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }

	m_ui.emailParticipants->selectionModel()->clear();
	m_ui.outgoingMessage->clear();
	m_ui.outgoingMessage->setCurrentCharFormat(QTextCharFormat());
	m_ui.outgoingSubject->clear();
	m_ui.goldbug->clear();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  m_ui.outgoingSubject->setFocus();
}

void spoton::slotDeleteAllBlockedNeighbors(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique blocked neighbors.
  ** Do remember that remote_ip_address contains encrypted data.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QMultiHash<QByteArray, qint64> hash;
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, OID FROM neighbors "
		      "WHERE status_control = 'blocked' ORDER BY OID"))
	  while(query.next())
	    {
	      QByteArray ip;
	      bool ok = true;

	      ip = s_crypt->
		decrypted(QByteArray::fromBase64(query.value(0).
						 toByteArray()),
			  &ok);

	      if(ok)
		hash.insert(ip, query.value(1).toLongLong());
	    }

	query.prepare("DELETE FROM neighbors WHERE OID = ?");

	for(int i = 0; i < hash.keys().size(); i++)
	  {
	    QList<qint64> list(hash.values(hash.keys().at(i)));

	    qSort(list);

	    for(int j = 1; j < list.size(); j++) // Delete all but one.
	      {
		query.bindValue(0, list.at(j));
		query.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotCopyMyEmailPublicKey(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyEmailPublicKey());
}

void spoton::slotCopyMyRosettaPublicKey(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyRosettaPublicKey());
}

QByteArray spoton::copyMyEmailPublicKey(void) const
{
  if(!m_crypts.value("email", 0) ||
     !m_crypts.value("email-signature", 0))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  bool ok = true;

  name = m_settings.value("gui/emailName", "unknown").toByteArray().
    trimmed();
  mPublicKey = m_crypts.value("email")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("email")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("email-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("email-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("email").toBase64() + "@" +
      name.toBase64() + "@" +
      mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QByteArray spoton::copyMyRosettaPublicKey(void) const
{
  if(!m_crypts.value("rosetta", 0) ||
     !m_crypts.value("rosetta-signature", 0))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  bool ok = true;

  name = m_settings.value("gui/rosettaName", "unknown").toByteArray().
    trimmed();
  mPublicKey = m_crypts.value("rosetta")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("rosetta")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("rosetta-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("rosetta-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("rosetta").toBase64() + "@" +
      name.toBase64() + "@" +
      mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QByteArray spoton::copyMyUrlPublicKey(void) const
{
  if(!m_crypts.value("url", 0) ||
     !m_crypts.value("url-signature", 0))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  bool ok = true;

  name = m_settings.value("gui/urlName", "unknown").toByteArray().
    trimmed();
  mPublicKey = m_crypts.value("url")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("url")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("url-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("url-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("url").toBase64() + "@" +
      name.toBase64() + "@" +
      mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

void spoton::slotCopyMyURLPublicKey(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyUrlPublicKey());
}

void spoton::slotShareURLPublicKey(void)
{
  if(!m_crypts.value("url", 0) ||
     !m_crypts.value("url-signature", 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypts.value("url")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("url")->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("url-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("url-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/urlName", "unknown").
		      toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid);
      message.append("_");
      message.append(QByteArray("url").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append('\n');

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotShareURLPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotDeleteAllUuids(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique uuids.
  ** Do remember that uuid contains encrypted data.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QMultiHash<QByteArray, qint64> hash;
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT uuid, OID FROM neighbors ORDER BY OID"))
	  while(query.next())
	    {
	      QByteArray uuid;
	      bool ok = true;

	      uuid = s_crypt->
		decrypted(QByteArray::fromBase64(query.value(0).
						 toByteArray()),
			  &ok);

	      if(ok)
		hash.insert(uuid, query.value(1).toLongLong());
	    }

	query.prepare("DELETE FROM neighbors WHERE OID = ?");

	for(int i = 0; i < hash.keys().size(); i++)
	  {
	    QList<qint64> list(hash.values(hash.keys().at(i)));

	    qSort(list);

	    for(int j = 1; j < list.size(); j++) // Delete all but one.
	      {
		query.bindValue(0, list.at(j));
		query.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotRefreshMail(void)
{
  if(m_ui.mailTab->currentIndex() != 0)
    return;

  m_ui.reply->setEnabled(m_ui.folder->currentIndex() == 0);

  if(m_ui.folder->currentIndex() == 0)
    {
      m_sb.email->setVisible(false);
      m_ui.mail->horizontalHeaderItem(1)->setText(tr("From"));
    }
  else if(m_ui.folder->currentIndex() == 1)
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("To"));
  else
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("From/To"));

  if(!m_crypts.value("email", 0))
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.mail->clearContents();
	m_ui.mail->setRowCount(0);
	m_ui.mail->setSortingEnabled(false);
	m_ui.mailMessage->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT date, receiver_sender, status, "
			      "subject, goldbug, "
			      "message, message_code, "
			      "receiver_sender_hash, "
			      "OID FROM folders WHERE "
			      "folder_index = %1").
		      arg(m_ui.folder->currentIndex())))
	  {
	    int row = 0;

	    while(query.next())
	      {
		QString goldbug("");
		bool ok = true;

		goldbug = m_crypts.value("email")->
		  decrypted(QByteArray::
			    fromBase64(query.
				       value(4).
				       toByteArray()),
			    &ok).constData();

		if(goldbug.isEmpty())
		  goldbug = "0";

		for(int i = 0; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = 0;

		    if(i == 0)
		      {
			row += 1;
			m_ui.mail->setRowCount(row);
		      }

		    if(i == 0 || i == 1 || i == 2 ||
		       i == 3 || i == 5 || i == 6)
		      {
			if(i == 1 || i == 2 || i == 3 || i == 5)
			  {
			    if(goldbug == "0")
			      {
				item = new QTableWidgetItem
				  (QString::
				   fromUtf8(m_crypts.value("email")->
					    decrypted(QByteArray::
						      fromBase64(query.
								 value(i).
								 toByteArray()),
						      &ok).constData()));

				if(!ok)
				  item->setText(tr("error"));
			      }
			    else
			      item = new QTableWidgetItem("#####");
			  }
			else
			  {
			    if(goldbug == "0")
			      {
				item = new QTableWidgetItem
				  (m_crypts.value("email")->
				   decrypted(QByteArray::
					     fromBase64(query.
							value(i).
							toByteArray()),
					     &ok).constData());

				if(!ok)
				  item->setText(tr("error"));
			      }
			    else
			      item = new QTableWidgetItem("#####");
			  }
		      }
		    else if(i == 4)
		      item = new QTableWidgetItem(goldbug);
		    else
		      item = new QTableWidgetItem(query.value(i).toString());

		    item->setFlags
		      (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		    m_ui.mail->setItem(row - 1, i, item);
		  }
	      }
	  }

	m_ui.mail->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotRefreshPostOffice(void)
{
  if(!m_crypts.value("email", 0))
    return;
  else if(m_ui.mailTab->currentIndex() != 2)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.postoffice->clearContents();
	m_ui.postoffice->setRowCount(0);
	m_ui.postoffice->setSortingEnabled(false);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT date_received, "
		      "message_bundle, recipient_hash "
		      "FROM post_office"))
	  {
	    int row = 0;

	    while(query.next())
	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;
		  bool ok = true;

		  if(i == 0)
		    {
		      row += 1;
		      m_ui.postoffice->setRowCount(row);
		    }

		  if(i == 0)
		    {
		      item = new QTableWidgetItem
			(m_crypts.value("email")->
			 decrypted(QByteArray::
				   fromBase64(query.
					      value(i).
					      toByteArray()),
				   &ok).constData());

		      if(!ok)
			item->setText(tr("error"));
		    }
		  else if(i == 1)
		    {
		      QByteArray bytes
			(m_crypts.value("email")->
			 decrypted(QByteArray::
				   fromBase64(query.
					      value(i).
					      toByteArray()),
				   &ok));

		      if(ok)
			item = new QTableWidgetItem
			  (QString::number(bytes.length()));
		      else
			item = new QTableWidgetItem(tr("error"));
		    }
		  else
		    item = new QTableWidgetItem(query.value(i).toString());

		  item->setFlags
		    (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		  m_ui.postoffice->setItem(row - 1, i, item);
		}
	  }

	m_ui.postoffice->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotMailSelected(QTableWidgetItem *item)
{
  if(!item)
    return;

  int row = item->row();

  if(row < 0)
    {
      m_ui.mailMessage->clear();
      return;
    }

  {
    QString goldbug("");
    QTableWidgetItem *item = m_ui.mail->item(row, 4); // Goldbug

    if(item)
      goldbug = item->text();

    if(goldbug == "1")
      {
	bool ok = true;

	goldbug = QInputDialog::getText
	  (this, tr("Spot-On: Goldbug"), tr("&Goldbug"),
	   QLineEdit::Password, QString(""), &ok).trimmed();

	if(!ok)
	  return;

	int rc = applyGoldbugToInboxLetter(goldbug.toLatin1(), row);

	if(rc == APPLY_GOLDBUG_TO_INBOX_ERROR_GENERAL)
	  {
	    QMessageBox::critical(this, tr("Spot-On: Error"),
				  tr("The provided goldbug may be "
				     "incorrect."));
	    return;
	  }
	else if(rc == APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY)
	  {
	    QMessageBox::critical(this, tr("Spot-On: Error"),
				  tr("A severe memory issue occurred."));
	    return;
	  }
	else
	  row = item->row(); // Sorting.
      }
  }

  QString date("");
  QString fromTo("");
  QString message("");
  QString status("");
  QString subject("");
  QString text("");

  {
    QTableWidgetItem *item = m_ui.mail->item(row, 0); // Date

    if(item)
      date = item->text();

    item = m_ui.mail->item(row, 1); // From / To

    if(item)
      fromTo = item->text();

    item = m_ui.mail->item(row, 2); // Status

    if(item)
      status = item->text();

    item = m_ui.mail->item(row, 3); // Subject

    if(item)
      subject = item->text();

    item = m_ui.mail->item(row, 5); // Message

    if(item)
      message = item->text();
  }

  if(m_ui.folder->currentIndex() == 0) // Inbox
    {
      text.append(tr("<b>From:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>To:</b> me"));
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<br>");
      text.append("<span style=\"font-size:large;\">");
      text.append(message);
      text.append("</span>");

      if(status != tr("Read"))
	{
	  QTableWidgetItem *item = 0;

	  if((item = m_ui.mail->
	      item(row, m_ui.mail->columnCount() - 1))) // OID
	    if(updateMailStatus(item->text(), tr("Read")))
	      if((item = m_ui.mail->item(row, 2))) // Status
		item->setText(tr("Read"));
	}
    }
  else if(m_ui.folder->currentIndex() == 1) // Sent
    {
      text.append(tr("<b>From:</b> me"));
      text.append("<br>");
      text.append(tr("<b>To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<br>");
      text.append(message);
    }
  else // Trash
    {
      text.append(tr("<b>From/To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>From/To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<br>");
      text.append(message);

      if(status != tr("Deleted"))
	{
	  QTableWidgetItem *item = 0;

	  if((item = m_ui.mail->
	      item(row, m_ui.mail->columnCount() - 1))) // OID
	    if(updateMailStatus(item->text(), tr("Deleted")))
	      if((item = m_ui.mail->item(row, 2))) // Status
		item->setText(tr("Deleted"));
	}
    }

  m_ui.mailMessage->clear();
  m_ui.mailMessage->append(text);
  m_ui.mailMessage->horizontalScrollBar()->setValue(0);
  m_ui.mailMessage->verticalScrollBar()->setValue(0);
}

void spoton::slotDeleteMail(void)
{
  if(m_ui.mailTab->currentIndex() != 0)
    return;

  QModelIndexList list
    (m_ui.mail->selectionModel()->
     selectedRows(m_ui.mail->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QString oid(list.takeFirst().data().toString());
	    bool ok = true;

	    if(m_ui.folder->currentIndex() == 2) // Trash
	      {
		query.prepare("DELETE FROM folders WHERE OID = ?");
		query.bindValue(0, oid);
	      }
	    else
	      {
		query.prepare("UPDATE folders SET folder_index = 2, "
			      "status = ? WHERE "
			      "OID = ?");

		if(m_crypts.value("email", 0))
		  query.bindValue
		    (0, m_crypts.value("email")->
		     encrypted(tr("Deleted").toUtf8(), &ok).
		     toBase64());
		else
		  ok = false;

		query.bindValue(1, oid);
	      }

	    if(ok)
	      if(!query.exec())
		/*
		** We may be attempting to delete a letter from the
		** inbox that also exists in the trash. This can occur
		** whenever we request e-mail from other offices that was
		** also delivered to us.
		** The letter's date in the trash folder will be stale.
		*/

		if(query.lastError().text().toLower().contains("unique"))
		  {
		    QSqlQuery query(db);

		    query.prepare("DELETE FROM folders WHERE OID = ?");
		    query.bindValue(0, oid);
		    query.exec();
		  }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  slotRefreshMail();
}

void spoton::slotGeminiChanged(QTableWidgetItem *item)
{
  if(!item)
    return;
  else if(!(item->column() == 6 ||
	    item->column() == 7)) // Gemini E. Key, Gemini H. Key
    return;
  else if(!m_ui.participants->item(item->row(), 1)) // OID
    return;

  QTableWidgetItem *item1 = 0;
  QTableWidgetItem *item2 = 0;

  if(item->column() == 6)
    {
      item1 = item;
      item2 = m_ui.participants->item(item->row(), 7);
    }
  else
    {
      item1 = m_ui.participants->item(item->row(), 6);
      item2 = item;
    }

  if(!item1 || !item2)
    return;

  QPair<QByteArray, QByteArray> gemini;

  gemini.first = item1->text().trimmed().toLatin1();
  gemini.second = item2->text().trimmed().toLatin1();
  saveGemini(gemini,
	     m_ui.participants->item(item->row(), 1)->text()); // OID
}

void spoton::slotGenerateGeminiInChat(void)
{
  int row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  QTableWidgetItem *item1 = m_ui.participants->item(row, 1); // OID
  QTableWidgetItem *item2 = m_ui.participants->item(row, 6); // Gemini E. Key
  QTableWidgetItem *item3 = m_ui.participants->item(row, 7); // Gemini H. Key

  if(!item1 || !item2 || !item3)
    return;

  QPair<QByteArray, QByteArray> gemini;

  gemini.first = spoton_crypt::
    strongRandomBytes(spoton_crypt::cipherKeyLength("aes256"));
  gemini.second = spoton_crypt::strongRandomBytes
    (spoton_crypt::cipherKeyLength("aes256"));

  if(saveGemini(gemini, item1->text()))
    {
      disconnect(m_ui.participants,
		 SIGNAL(itemChanged(QTableWidgetItem *)),
		 this,
		 SLOT(slotGeminiChanged(QTableWidgetItem *)));
      item2->setText(gemini.first.toBase64());
      item3->setText(gemini.second.toBase64());
      connect(m_ui.participants,
	      SIGNAL(itemChanged(QTableWidgetItem *)),
	      this,
	      SLOT(slotGeminiChanged(QTableWidgetItem *)));
    }
}

bool spoton::saveGemini(const QPair<QByteArray, QByteArray> &gemini,
			const QString &oid)
{
  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ? WHERE OID = ?");

	if(gemini.first.isEmpty() || gemini.second.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    if(m_crypts.value("chat", 0))
	      {
		query.bindValue(0, m_crypts.value("chat")->
				encrypted(gemini.first, &ok).toBase64());

		if(ok)
		  query.bindValue(1, m_crypts.value("chat")->
				  encrypted(gemini.second, &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
	      }
	  }

	query.bindValue(2, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

void spoton::slotGenerateGoldBug(void)
{
  QByteArray goldbug
    (spoton_crypt::
     strongRandomBytes(spoton_crypt::cipherKeyLength("aes256")));

  m_ui.goldbug->setText(goldbug.toBase64());
}

void spoton::slotEmptyTrash(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to empty the Trash folder?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM folders WHERE folder_index = 2");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_ui.folder->currentIndex() == 2)
    {
      m_ui.mail->clearContents();
      m_ui.mail->setRowCount(0);
      m_ui.mailMessage->clear();
    }
}

void spoton::slotEnableRetrieveMail(void)
{
  m_ui.retrieveMail->setEnabled(true);
}

void spoton::slotRetrieveMail(void)
{
  QString error("");

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    {
      if(m_kernelSocket.isEncrypted())
	{
	  QByteArray message("retrievemail\n");

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    spoton_misc::logError
	      (QString("spoton::slotRetrieveMail(): write() failure "
		       "for %1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	  else
	    {
	      m_kernelSocket.flush();
	      m_ui.retrieveMail->setEnabled(false);
	      QTimer::singleShot
		(5000, this, SLOT(slotEnableRetrieveMail(void)));
	    }
	}
      else
	error = tr("The connection to the kernel is not encrypted.");
    }
  else
    error = tr("Not connected to the kernel.");

  if(m_ui.retrieveMail == sender())
    if(!error.isEmpty())
      QMessageBox::critical(this, tr("Spot-On: Error"), error);
}

void spoton::slotKernelStatus(void)
{
  if(isKernelActive())
    slotDeactivateKernel();
  else
    slotActivateKernel();
}

void spoton::slotMailTabChanged(int index)
{
  /*
  ** Change states of some widgets.
  */

  m_ui.pushButtonClearMail->setEnabled(index != 2);
}

void spoton::slotEnabledPostOffice(bool state)
{
  m_settings["gui/postoffice_enabled"] = state;

  QSettings settings;

  settings.setValue("gui/postoffice_enabled", state);
}

void spoton::slotStatusButtonClicked(void)
{
  QToolButton *toolButton = qobject_cast<QToolButton *> (sender());

  if(toolButton == m_sb.buzz)
    {
      m_sb.buzz->setVisible(false);
      m_ui.tab->setCurrentIndex(0);
    }
  else if(toolButton == m_sb.chat)
    {
      m_sb.chat->setVisible(false);
      m_ui.tab->setCurrentIndex(1);
    }
  else if(toolButton == m_sb.email)
    {
      m_sb.email->setVisible(false);
      m_ui.folder->setCurrentIndex(0);
      m_ui.mailTab->setCurrentIndex(0);
      m_ui.tab->setCurrentIndex(2);
      slotRefreshMail();
    }
  else if(toolButton == m_sb.listeners)
    m_ui.tab->setCurrentIndex(3);
  else if(toolButton == m_sb.neighbors)
    m_ui.tab->setCurrentIndex(4);
}

bool spoton::updateMailStatus(const QString &oid, const QString &status)
{
  if(!m_crypts.value("email", 0))
    return false;

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE folders SET status = ? WHERE "
		      "OID = ?");
	query.bindValue
	  (0, m_crypts.value("email")->
	   encrypted(status.toUtf8(), &ok).toBase64());
	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

void spoton::slotKeepCopy(bool state)
{
  m_settings["gui/saveCopy"] = state;

  QSettings settings;

  settings.setValue("gui/saveCopy", state);
}

void spoton::slotSetIcons(void)
{
  QAction *action = qobject_cast<QAction *> (sender());
  QString iconSet("nouve");

  if(action)
    {
      action->setChecked(true); /*
				** Do not allow the user to uncheck
				** the checked action.
				*/

      for(int i = 0; i < m_ui.menu_Icons->actions().size(); i++)
	if(action != m_ui.menu_Icons->actions().at(i))
	  m_ui.menu_Icons->actions().at(i)->setChecked(false);

      QSettings settings;

      if(action == m_ui.actionNouve)
	iconSet = "nouve";
      else
	iconSet = "nuvola";

      m_settings["gui/iconSet"] = iconSet;
      settings.setValue("gui/iconSet", iconSet);
    }

  /*
  ** Kernel, listeners, and neighbors status icons are prepared elsewhere.
  */

  // Generic

  m_ui.action_Log_Viewer->setIcon
    (QIcon(QString(":/%1/information.png").arg(iconSet)));

  QStringList list;

  // Buzz

  m_ui.join->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.saveBuzzName->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));

  // Chat

  m_ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.saveEmailName->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_ui.saveNodeName->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_ui.sendMessage->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  list.clear();
  list << "away.png" << "busy.png" << "offline.png" << "online.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.status->setItemIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  // Email

  m_ui.pushButtonClearMail->setIcon
    (QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.refreshMail->setIcon(QIcon(QString(":/%1/refresh.png").arg(iconSet)));
  m_ui.reply->setIcon(QIcon(QString(":/%1/reply.png").arg(iconSet)));
  m_ui.retrieveMail->setIcon(QIcon(QString(":/%1/down.png").arg(iconSet)));
  m_ui.emptyTrash->setIcon
    (QIcon(QString(":/%1/empty-trash.png").arg(iconSet)));
  m_ui.generateGoldBug->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));
  m_ui.sendMail->setIcon(QIcon(QString(":/%1/email.png").arg(iconSet)));
  list.clear();
  list << "inbox.png" << "outbox.png" << "full-trash.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.folder->setItemIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  list.clear();
  list << "read.png" << "write.png" << "database.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.mailTab->setTabIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  // Listeners

  m_ui.addAcceptedIP->setIcon(QIcon(QString(":/%1/add.png").
				    arg(iconSet)));
  m_ui.addAccount->setIcon(QIcon(QString(":/%1/add.png").
				 arg(iconSet)));
  m_ui.addListener->setIcon(QIcon(QString(":/%1/add-listener.png").
				  arg(iconSet)));
  m_ui.deleteAccount->setIcon(QIcon(QString(":/%1/clear.png").
				    arg(iconSet)));
  m_ui.deleteAcceptedIP->setIcon(QIcon(QString(":/%1/clear.png").
				       arg(iconSet)));

  // Login

  m_ui.passphraseButton->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();

  // Neighbors

  m_ui.toolButtonCopyToClipboard->setIcon
    (QIcon(QString(":/%1/copy.png").arg(iconSet)));
  m_ui.shareBuzzMagnet->setIcon
    (QIcon(QString(":/%1/share.png").arg(iconSet)));
  m_ui.addNeighbor->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.addFriend->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.clearFriend->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));

  // Search

  m_ui.deleteURL->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.modifyURL->setIcon(QIcon(QString(":/%1/modify.png").arg(iconSet)));
  m_ui.searchURL->setIcon(QIcon(QString(":/%1/search.png").arg(iconSet)));

  // Settings

  m_ui.activateKernel->setIcon
    (QIcon(QString(":/%1/activate.png").arg(iconSet)));
  m_ui.deactivateKernel->setIcon
    (QIcon(QString(":/%1/deactivate.png").arg(iconSet)));
  m_ui.setPassphrase->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));

  // StarBeam

  m_ui.addMagnet->setIcon(QIcon(QString(":/%1/add.png").
				arg(iconSet)));
  m_ui.addNova->setIcon(QIcon(QString(":/%1/add.png").
			      arg(iconSet)));
  m_ui.deleteNova->setIcon(QIcon(QString(":/%1/clear.png").
				 arg(iconSet)));
  m_ui.generateNova->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));

  // Status

  m_sb.authentication_request->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));
  m_sb.buzz->setIcon(QIcon(QString(":/%1/buzz.png").arg(iconSet)));
  m_sb.chat->setIcon(QIcon(QString(":/%1/chat.png").arg(iconSet)));
  m_sb.email->setIcon(QIcon(QString(":/%1/email.png").arg(iconSet)));
  m_sb.errorlog->setIcon(QIcon(QString(":/%1/information.png").arg(iconSet)));

  // Tab

  list.clear();
  list << "buzz.png" << "chat.png" << "email.png"
       << "add-listener.png" << "neighbors.png"
       << "settings.png" << "starbeam.png" << "urls.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.tab->setTabIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  // URLs

  m_ui.addDLDistiller->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.delDLDistiller->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.addULDistiller->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.delULDistiller->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (0, QIcon(QString(":/%1/down.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (1, QIcon(QString(":/%1/up.png").arg(iconSet)));
  emit iconsChanged();
}

int spoton::applyGoldbugToInboxLetter(const QByteArray &goldbug,
				      const int row)
{
  if(!m_crypts.value("email", 0))
    return APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY;

  QTableWidgetItem *item = m_ui.mail->item
    (row, m_ui.mail->columnCount() - 1); // OID

  if(!item)
    return APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY;

  QString connectionName("");
  QString oid(item->text());
  bool ok = true;
  int rc = 0;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if((ok = db.open()))
      {
	QList<QByteArray> list;
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT date, message, message_code, "
		      "receiver_sender, receiver_sender_hash, "
		      "subject FROM folders "
		      "WHERE OID = ?");
	query.bindValue(0, oid);

	if((ok = query.exec()))
	  if((ok = query.next()))
	    for(int i = 0; i < query.record().count(); i++)
	      {
		if(i == 2 || i == 4)
		  list.append
		    (QByteArray::fromBase64(query.value(i).
					    toByteArray()).trimmed());
		else
		  list.append
		    (m_crypts.value("email")->
		     decrypted(QByteArray::
			       fromBase64(query.
					  value(i).
					  toByteArray()),
			       &ok).trimmed());

		if(!ok)
		  break;
	      }

	if(ok)
	  {
	    spoton_crypt crypt("aes256",
			       QString("sha512"),
			       QByteArray(),
			       goldbug,
			       0,
			       0,
			       QString(""));

	    for(int i = 0; i < list.size(); i++)
	      {
		if(i == 0 || i == 2 || i == 4)
		  /*
		  ** Ignore the date, message_code, and
		  ** receiver_sender_hash columns.
		  */

		  continue;

		list.replace(i, crypt.decrypted(list.at(i), &ok));

		if(!ok)
		  break;
	      }
	  }

	if(ok)
	  {
	    /*
	    ** list[0]: date
	    ** list[1]: message
	    ** list[2]: message_code
	    ** list[3]: receiver_sender
	    ** list[4]: receiver_sender_hash
	    ** list[5]: subject
	    */

	    QSqlQuery updateQuery(db);

	    updateQuery.prepare("UPDATE folders SET "
				"goldbug = ?, "
				"hash = ?, "
				"message = ?, "
				"message_code = ?, "
				"receiver_sender = ?, "
				"subject = ? "
				"WHERE OID = ?");

	    if(ok)
	      updateQuery.bindValue
		(0, m_crypts.value("email")->
		 encrypted(QByteArray::number(0), &ok).
		 toBase64());

	    if(ok)
	      updateQuery.bindValue
		(1, m_crypts.value("email")->
		 keyedHash(list.value(1) + list.value(5), &ok).
		 toBase64());

	    if(!list.value(1).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (2, m_crypts.value("email")->
		   encrypted(list.value(1), &ok).toBase64());

	    if(!list.value(2).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (3, m_crypts.value("email")->
		   encrypted(QByteArray(), &ok).toBase64());

	    if(!list.value(3).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (4, m_crypts.value("email")->
		   encrypted(list.value(3), &ok).toBase64());

	    if(!list.value(5).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (5, m_crypts.value("email")->
		   encrypted(list.value(5), &ok).toBase64());

	    updateQuery.bindValue(6, oid);

	    if(ok)
	      {
		ok = updateQuery.exec();

		if(!ok)
		  if(updateQuery.lastError().text().
		     toLower().contains("unique"))
		    ok = true;
	      }
	  }

	if(ok)
	  {
	    m_ui.mail->setSortingEnabled(false);

	    QTableWidgetItem *item = m_ui.mail->item(row, 0); // Date

	    if(item)
	      item->setText(list.value(0).constData());

	    item = m_ui.mail->item(row, 1); // From / To

	    if(item)
	      item->setText(list.value(3).constData());

	    item = m_ui.mail->item(row, 3); // Subject

	    if(item)
	      item->setText(list.value(5).constData());

	    item = m_ui.mail->item(row, 4); // Goldbug

	    if(item)
	      item->setText("0");

	    item = m_ui.mail->item(row, 5); // Message

	    if(item)
	      item->setText(list.value(1).constData());

	    m_ui.mail->setSortingEnabled(true);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    if(rc == 0)
      rc = APPLY_GOLDBUG_TO_INBOX_ERROR_GENERAL;

  return rc;
}

void spoton::slotCostChanged(int value)
{
  m_settings["gui/congestionCost"] = value;

  QSettings settings;

  settings.setValue("gui/congestionCost", value);
}

void spoton::slotDaysChanged(int value)
{
  m_settings["gui/postofficeDays"] = value;

  QSettings settings;

  settings.setValue("gui/postofficeDays", value);
}

void spoton::slotReply(void)
{
  int row = m_ui.mail->currentRow();

  if(row < 0)
    return;

  QTableWidgetItem *item = m_ui.mail->item(row, 4); // Goldbug

  if(!item)
    return;

  if(item->text() != "0")
    /*
    ** How can we reply to an encrypted message?
    */

    return;

  item = m_ui.mail->item(row, 5); // Message

  if(!item)
    return;

  QString message(item->text());

  item = m_ui.mail->item(row, 7); // receiver_sender_hash

  if(!item)
    return;

  QString receiverSenderHash(item->text());

  item = m_ui.mail->item(row, 3); // Subject

  if(!item)
    return;

  QString subject(item->text());

  message = "<br><span style=\"font-size:large;\">" + message + "</span>";
  m_ui.outgoingMessage->setHtml(message);
  m_ui.outgoingSubject->setText(tr("Re: ") + subject);
  m_ui.mailTab->setCurrentIndex(1);

  /*
  ** The original author may have vanished.
  */

  m_ui.emailParticipants->selectionModel()->clear();

  for(int i = 0; i < m_ui.emailParticipants->rowCount(); i++)
    {
      QTableWidgetItem *item = m_ui.emailParticipants->
	item(i, 3); // public_key_hash

      if(item)
	if(item->text() == receiverSenderHash)
	  {
	    m_ui.emailParticipants->selectRow(i);
	    break;
	  }
    }

  m_ui.outgoingMessage->moveCursor(QTextCursor::Start);
  m_ui.outgoingMessage->setFocus();
}

void spoton::slotPublicizeAllListenersPlaintext(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QByteArray message;

  message.append("publicizealllistenersplaintext\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotPublicizeAllListenersPlaintext(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
  else
    m_kernelSocket.flush();
}

void spoton::slotPublicizeListenerPlaintext(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray message;

  message.append("publicizelistenerplaintext_");
  message.append(oid);
  message.append('\n');

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotPublicizeListenerPlaintext(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
  else
    m_kernelSocket.flush();
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
bool spoton::event(QEvent *event)
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
	  show();
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif

void spoton::slotSuperEcho(bool state)
{
  m_settings["gui/superEcho"] = state;

  QSettings settings;

  settings.setValue("gui/superEcho", state);
}

void spoton::slotKernelKeySizeChanged(const QString &text)
{
  m_settings["gui/kernelKeySize"] = text.toInt();

  QSettings settings;

  settings.setValue
    ("gui/kernelKeySize",
     m_settings.value("gui/kernelKeySize"));
}

void spoton::slotPublishedKeySizeChanged(const QString &text)
{
  m_settings["gui/publishedKeySize"] = text.toInt();

  QSettings settings;

  settings.setValue
    ("gui/publishedKeySize",
     m_settings.value("gui/publishedKeySize"));
}

void spoton::slotJoinBuzzChannel(void)
{
  QByteArray channel(m_ui.channel->text().trimmed().toLatin1());
  QByteArray channelSalt;
  QByteArray channelType(m_ui.channelType->currentText().toLatin1());
  QByteArray hashKey(m_ui.buzzHashKey->text().trimmed().toLatin1());
  QByteArray hashType(m_ui.buzzHashType->currentText().toLatin1());
  QByteArray id;
  QPair<QByteArray, QByteArray> keys;
  QString error("");
  bool found = false;
  bool ok = true;
  spoton_buzzpage *page = 0;
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);
  unsigned long iterationCount = m_ui.buzzIterationCount->value();

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if(channel.isEmpty())
    {
      error = tr("Please provide a channel name.");
      goto done_label;
    }

  channelSalt = m_ui.channelSalt->text().trimmed().toLatin1();

  if(channelSalt.isEmpty())
    channelSalt = spoton_crypt::keyedHash(channel + channelType,
					  channel, "sha512", &ok);

  if(!ok)
    {
      error = tr("Unable to compute a keyed hash.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys(m_ui.channelType->currentText(),
				   "sha512",
				   iterationCount,
				   m_ui.channel->text().trimmed(),
				   channelSalt,
				   error);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    goto done_label;

  foreach(spoton_buzzpage *page,
	  m_ui.buzzTab->findChildren<spoton_buzzpage *> ())
    if(keys.first == page->key())
      {
	found = true;
	m_ui.buzzTab->setCurrentWidget(page);
	break;
      }

  if(found)
    goto done_label;

  if(hashKey.isEmpty())
    hashKey = keys.second.toBase64();;

  if(m_buzzIds.contains(keys.first))
    id = m_buzzIds[keys.first];
  else
    {
      id = spoton_crypt::
	strongRandomBytes(spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();
      m_buzzIds[keys.first] = id;
    }

  if(m_ui.channelSalt->text().trimmed().isEmpty())
    /*
    ** Reset the channelSalt container. We used it above to avoid
    ** duplicate Buzz keys.
    */

    channelSalt.clear();

  m_ui.channel->clear();
  m_ui.channelSalt->clear();
  m_ui.channelType->setCurrentIndex(0);
  m_ui.buzzIterationCount->setValue(m_ui.buzzIterationCount->minimum());
  m_ui.buzzHashKey->clear();
  m_ui.buzzHashType->setCurrentIndex(0);
  page = new spoton_buzzpage
    (&m_kernelSocket, channel, channelSalt, channelType,
     id, iterationCount, hashKey, hashType, s_crypt, this);
  connect(&m_buzzStatusTimer,
	  SIGNAL(timeout(void)),
	  page,
	  SLOT(slotSendStatus(void)));
  connect(page,
	  SIGNAL(changed(void)),
	  this,
	  SLOT(slotBuzzChanged(void)));
  connect(page,
	  SIGNAL(channelSaved(void)),
	  this,
	  SLOT(slotPopulateBuzzFavorites(void)));
  connect(this,
	  SIGNAL(buzzNameChanged(const QByteArray &)),
	  page,
	  SLOT(slotBuzzNameChanged(const QByteArray &)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  page,
	  SLOT(slotSetIcons(void)));
  m_ui.buzzTab->addTab(page, QString::fromUtf8(channel.constData(),
					       channel.length()));
  m_ui.buzzTab->setCurrentIndex(m_ui.buzzTab->count() - 1);

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted())
      {
	QByteArray message("addbuzz_");

	message.append(page->key().toBase64());
	message.append("_");
	message.append(page->channelType().toBase64());
	message.append("_");
	message.append(page->hashKey().toBase64());
	message.append("_");
	message.append(page->hashType().toBase64());
	message.append("\n");

	if(m_kernelSocket.write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton::slotJoinBuzzChannel(): "
		     "write() failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
	else
	  m_kernelSocket.flush();
      }

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
}

void spoton::slotCloseBuzzTab(int index)
{
  QByteArray key;
  int count = 0;
  spoton_buzzpage *page = qobject_cast<spoton_buzzpage *>
    (m_ui.buzzTab->widget(index));

  count = m_ui.buzzTab->count();

  if(page)
    {
      key = page->key();
      count -= 1;
      page->deleteLater();
    }

  if(!count)
    m_buzzStatusTimer.stop();

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted())
      {
	QByteArray message("removebuzz_");

	message.append(key.toBase64());
	message.append("\n");

	if(m_kernelSocket.write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton::slotCloseBuzzTab(): write() failure "
		     "for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
	else
	  m_kernelSocket.flush();
      }
}

void spoton::initializeKernelSocket(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText
    (tr("Generating SSL data for kernel socket. Please be patient."));

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  spoton_crypt::generateSslKeys
    (m_ui.kernelKeySize->currentText().toInt(),
     certificate,
     privateKey,
     publicKey,
     m_kernelSocket.peerAddress(),
     60 * 60 * 24 * 7, // Seven days.
     error);
  m_sb.status->clear();
  QApplication::restoreOverrideCursor();

  if(error.isEmpty())
    {
      QSslConfiguration configuration;

      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));
#if QT_VERSION >= 0x040800
      configuration.setSslOption
	(QSsl::SslOptionDisableCompression, true);
      configuration.setSslOption
	(QSsl::SslOptionDisableEmptyFragments, true);
      configuration.setSslOption
	(QSsl::SslOptionDisableLegacyRenegotiation, true);
#endif
      spoton_crypt::setSslCiphers(QSslSocket::supportedCiphers(),
				  configuration);
      m_kernelSocket.setSslConfiguration(configuration);
    }
  else
    spoton_misc::logError
      (QString("spoton::"
	       "initializeKernelSocket(): "
	       "generateSslKeys() failure (%1).").arg(error.remove(".")));
}

void spoton::slotBuzzChanged(void)
{
  if(m_ui.tab->currentIndex() != 0)
    m_sb.buzz->setVisible(true);
}

void spoton::slotRemoveEmailParticipants(void)
{
  if(!m_ui.emailParticipants->selectionModel()->hasSelection())
    return;

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"participant(s)?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QModelIndexList list
	  (m_ui.emailParticipants->selectionModel()->
	   selectedRows(1)); // OID
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      {
		query.prepare("DELETE FROM friends_public_keys WHERE "
			      "OID = ?");
		query.bindValue(0, data.toString());
		query.exec();
	      }
	  }

	spoton_misc::purgeSignatureRelationships(db);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotAddAcceptedIP(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QMessageBox::critical
	(this, tr("Spot-On: Error"),
	 tr("Invalid listener OID. Please select a listener."));
      return;
    }

  QHostAddress ip(m_ui.acceptedIP->text().trimmed());

  if(m_ui.acceptedIP->text().trimmed() != "Any")
    if(ip.isNull())
      {
	QMessageBox::critical(this, tr("Spot-On: Error"),
			      tr("Please provide an IP address or "
				 "the keyword Any."));
	return;
      }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO listeners_allowed_ips "
	   "(ip_address, ip_address_hash, "
	   "listener_oid) "
	   "VALUES (?, ?, ?)");

	if(m_ui.acceptedIP->text().trimmed() == "Any")
	  {
	    query.bindValue
	      (0, s_crypt->encrypted("Any", &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, s_crypt->keyedHash("Any", &ok).
		 toBase64());
	  }
	else
	  {
	    query.bindValue
	      (0, s_crypt->encrypted(ip.toString().toLatin1(),
				     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, s_crypt->keyedHash(ip.toString().
				       toLatin1(), &ok).
		 toBase64());
	  }

	query.bindValue(2, oid);

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    m_ui.acceptedIP->clear();
  else
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("Unable to record the IP address."));
}

void spoton::slotDeleteAccepedIP(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid listener OID. "
			       "Please select a listener."));
      return;
    }

  QString ip("");

  if((row = m_ui.acceptedIPList->currentRow()) >= 0)
    {
      QListWidgetItem *item = m_ui.acceptedIPList->item(row);

      if(item)
	ip = item->text();
    }

  if(ip.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Please select an address to delete."));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("DELETE FROM listeners_allowed_ips WHERE "
		      "ip_address_hash = ? AND listener_oid = ?");
	query.bindValue
	  (0, s_crypt->keyedHash(ip.toLatin1(),
				 &ok).toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(ip == "Any")
	  query.exec
	    ("UPDATE neighbors SET status_control = 'disconnected'");
	else
	  {
	    bool ok = true;

	    query.prepare("UPDATE neighbors SET "
			  "status_control = 'disconnected' "
			  "WHERE remote_ip_address_hash = ?");
	    query.bindValue
	      (0,
	       s_crypt->keyedHash(ip.toLatin1(), &ok).
	       toBase64());

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(row > -1)
    delete m_ui.acceptedIPList->takeItem(row);
}

void spoton::slotTestSslControlString(void)
{
  QList<QSslCipher> ciphers
    (spoton_crypt::defaultSslCiphers(m_ui.sslControlString->text()));
  QMessageBox mb(this);
  QString str("");

  for(int i = 0; i < ciphers.size(); i++)
    str.append(QString("%1-%2").arg(ciphers.at(i).name()).
	       arg(ciphers.at(i).protocolString()) + "\n");

  if(!str.isEmpty())
    {
      mb.setDetailedText(str);
      mb.setText(tr("The following ciphers were discovered. Please "
		    "note that Spot-On may neglect discovered ciphers "
		    "if the ciphers are not supported by Qt."));
    }
  else
    mb.setText(tr("Empty cipher list."));

  mb.setStandardButtons(QMessageBox::Ok);
  mb.setWindowTitle(tr("Spot-On: Information"));
  mb.exec();
}

void spoton::slotChatInactivityTimeout(void)
{
  if(m_ui.status->currentIndex() != 2) // Offline
    m_ui.status->setCurrentIndex(0); // Away
}

void spoton::slotAddAccount(void)
{
  QString connectionName("");
  QString error("");
  QString name(m_ui.accountName->text().trimmed());
  QString oid("");
  QString password(m_ui.accountPassword->text());
  bool ok = true;
  int row = -1;
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      error = tr("Invalid listener OID. Please select a listener.");
      goto done_label;
    }

  for(int i = name.length() - 1; i >= 0; i--)
    if(!name.at(i).isPrint())
      name.remove(i, 1);

  for(int i = password.length() - 1; i >= 0; i--)
    if(!password.at(i).isPrint())
      password.remove(i, 1);

  if(name.isEmpty() || password.isEmpty())
    {
      error = tr("Please provide an account name and an account password.");
      goto done_label;
    }
  else if(password.length() < 16)
    {
      error = tr("Please provide an account password that contains at "
		 "least sixteen characters.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO listeners_accounts "
		      "(account_name, "
		      "account_name_hash, "
		      "account_password, "
		      "listener_oid, "
		      "one_time_account) "
		      "VALUES (?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->encrypted(name.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->keyedHash(name.toLatin1(),
				   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->encrypted(password.toLatin1(), &ok).toBase64());

	query.bindValue(3, oid);
	query.bindValue(4, m_ui.ota->isChecked() ? 1 : 0);

	if(ok)
	  query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error has occurred.");

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
  else
    {
      m_ui.accountName->clear();
      m_ui.accountPassword->clear();
      m_ui.ota->setChecked(false);
      populateAccounts(oid);
    }
}

void spoton::slotDeleteAccount(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid listener OID. "
			       "Please select a listener."));
      return;
    }

  QList<QListWidgetItem *> list(m_ui.accounts->selectedItems());

  if(list.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Please select an account to delete."));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("DELETE FROM listeners_accounts WHERE "
		      "account_name_hash = ? AND listener_oid = ?");
	query.bindValue
	  (0, s_crypt->keyedHash(list.at(0)->text().toLatin1(), &ok).
	   toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateAccounts(oid);
}

void spoton::populateAccounts(const QString &listenerOid)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QListWidgetItem *item = m_ui.accounts->selectedItems().value(0);
	QString account("");

	if(item)
	  account = item->text();

	m_ui.accounts->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT account_name FROM listeners_accounts "
		      "WHERE listener_oid = ? AND "
		      "listener_oid IN (SELECT OID FROM listeners WHERE "
		      "status_control <> 'deleted' AND OID = ?)");
	query.bindValue(0, listenerOid);
	query.bindValue(1, listenerOid);

	if(query.exec())
	  {
	    QStringList names;

	    while(query.next())
	      {
		QString name("");
		bool ok = true;

		name = s_crypt->decrypted(QByteArray::
					  fromBase64(query.
						     value(0).
						     toByteArray()),
					  &ok).constData();

		if(!name.isEmpty())
		  names.append(name);
	      }

	    qSort(names);

	    if(!names.isEmpty())
	      m_ui.accounts->addItems(names);
	  }

	item = m_ui.accounts->findItems(account, Qt::MatchExactly).value(0);

	if(item)
	  item->setSelected(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::populateListenerIps(const QString &listenerOid)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QListWidgetItem *item = m_ui.acceptedIPList->selectedItems().value(0);
	QString ip("");

	if(item)
	  ip = item->text();

	m_ui.acceptedIPList->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT ip_address FROM listeners_allowed_ips "
		      "WHERE listener_oid = ? AND listener_oid IN "
		      "(SELECT OID FROM listeners WHERE status_control <> "
		      "'deleted' AND OID = ?)");
	query.bindValue(0, listenerOid);
	query.bindValue(1, listenerOid);

	if(query.exec())
	  {
	    QStringList ips;

	    while(query.next())
	      {
		QString ip("");
		bool ok = true;

		ip = s_crypt->decrypted(QByteArray::
					fromBase64(query.
						   value(0).
						   toByteArray()),
					&ok).constData();

		if(!ip.isEmpty())
		  ips.append(ip);
	      }

	    qSort(ips);

	    if(!ips.isEmpty())
	      m_ui.acceptedIPList->addItems(ips);
	  }

	item = m_ui.acceptedIPList->findItems(ip, Qt::MatchExactly).value(0);

	if(item)
	  item->setSelected(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotListenerSelected(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  populateAccounts(oid);
  populateListenerIps(oid);
}

void spoton::slotParticipantDoubleClicked(QTableWidgetItem *item)
{
  if(!item)
    return;

  if(item->data(Qt::UserRole).toBool()) // Temporary friend?
    return;
  else if(item->column() == 6 ||
	  item->column() == 7) // Gemini E. Key, Gemini H. Key?
    return;

  QIcon icon;
  QString oid("");
  QString participant("");
  QString publicKeyHash("");
  int row = item->row();

  item = m_ui.participants->item(row, 0); // Participant

  if(!item)
    return;

  icon = item->icon();
  participant = item->text();
  item = m_ui.participants->item(row, 1); // OID

  if(!item)
    return;

  oid = item->text();
  item = m_ui.participants->item(row, 3); // public_key_hash

  if(!item)
    return;

  publicKeyHash = item->text();

  if(m_chatWindows.contains(publicKeyHash))
    {
      QPointer<spoton_chatwindow> chat = m_chatWindows.value(publicKeyHash);

      if(chat)
	{
	  chat->showNormal();
	  chat->raise();
	}

      return;
    }

  QPointer<spoton_chatwindow> chat = new spoton_chatwindow
    (icon, oid, participant, &m_kernelSocket, 0);

  connect(chat,
	  SIGNAL(destroyed(void)),
	  this,
	  SLOT(slotChatWindowDestroyed(void)));
  connect(chat,
	  SIGNAL(messageSent(void)),
	  this,
	  SLOT(slotChatWindowMessageSent(void)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  chat,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(statusChanged(const QIcon &,
			       const QString &,
			       const QString &)),
	  chat,
	  SLOT(slotSetStatus(const QIcon &,
			     const QString &,
			     const QString &)));
  m_chatWindows[publicKeyHash] = chat;
  chat->center(this);
  chat->showNormal();
  chat->raise();
}

void spoton::slotChatWindowDestroyed(void)
{
  QMutableHashIterator<QString, QPointer<spoton_chatwindow> > it
    (m_chatWindows);

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	it.remove();
    }
}

void spoton::slotChatWindowMessageSent(void)
{
  if(m_ui.status->currentIndex() != 2) // Offline
    m_ui.status->setCurrentIndex(3); // Online

  m_chatInactivityTimer.start();
}

void spoton::authenticationRequested(const QByteArray &data)
{
  if(!data.isEmpty())
    if(!m_sb.authentication_request->isVisible())
      {
	m_sb.authentication_request->setProperty
	  ("data", data);
	m_sb.authentication_request->
	  setToolTip(tr("Remote user %1 is requesting authentication "
			"credentials.").arg(data.constData()));
	m_sb.authentication_request->setVisible(true);
	QTimer::singleShot(7500, m_sb.authentication_request,
			   SLOT(hide(void)));
      }
}

void spoton::slotAuthenticationRequestButtonClicked(void)
{
  m_sb.authentication_request->setVisible(false);
  m_ui.tab->setCurrentIndex(4); // Neighbors

  if(m_neighborToOidMap.contains(m_sb.authentication_request->
				 property("data").toByteArray()))
    authenticate(m_crypts.value("chat", 0),
		 m_neighborToOidMap.
		 value(m_sb.authentication_request->
		       property("data").toByteArray()),
		 m_sb.authentication_request->toolTip());
}
