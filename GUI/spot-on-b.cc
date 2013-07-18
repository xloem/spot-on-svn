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

#include "spot-on.h"
#include "spot-on-buzzpage.h"

void spoton::slotSendMessage(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_ui.message->toPlainText().trimmed().isEmpty())
    return;

  if(!m_ui.participants->selectionModel()->hasSelection())
    /*
    ** We need at least one participant.
    */

    return;

  QModelIndexList list(m_ui.participants->selectionModel()->selectedRows(1));
  QString message("");

  message.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  message.append(tr("<b>me:</b> "));
  message.append(m_ui.message->toPlainText().trimmed());
  m_ui.messages->append(message);
  m_ui.messages->verticalScrollBar()->setValue
    (m_ui.messages->verticalScrollBar()->maximum());

  while(!list.isEmpty())
    {
      QModelIndex index(list.takeFirst());
      QVariant data(index.data());

      if(!data.isNull() && data.isValid())
	{
	  QByteArray message("");
	  QByteArray name(m_settings.value("gui/nodeName", "unknown").
			  toByteArray().trimmed());

	  if(name.isEmpty())
	    name = "unknown";

	  message.append("message_");
	  message.append(QString("%1_").arg(data.toString()));
	  message.append(name.toBase64());
	  message.append("_");
	  message.append(m_ui.message->toPlainText().trimmed().toUtf8().
			 toBase64());
	  message.append('\n');

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    spoton_misc::logError
	      ("spoton::slotSendMessage(): write() failure.");
	  else
	    m_kernelSocket.flush();
	}
    }

  m_ui.message->clear();
}

void spoton::slotReceivedKernelMessage(void)
{
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

	  if(data.startsWith("buzz_"))
	    {
	      data.remove(0, strlen("buzz_"));

	      QList<QByteArray> list(data.split('_'));

	      if(!(list.size() == 2 || list.size() == 3))
		continue;

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      /*
	      ** Find the channel!
	      */

	      spoton_buzzpage *page = 0;

	      for(int i = 0; i < m_ui.buzzTab->count(); i++)
		{
		  QList<QByteArray> a(list);
		  bool ok = true;
		  spoton_crypt crypt("aes256",
				     QString(""),
				     QByteArray(),
				     m_ui.buzzTab->tabText(i).toLatin1(),
				     0,
				     0,
				     QString(""));

		  a.replace
		    (0,
		     crypt.decrypted(a.at(0), &ok)); /*
							** Let's hope that
							** we have a short
							** name.
							*/

		  if(ok)
		    {
		      a.replace
			(1,
			 crypt.decrypted(a.at(1), &ok));

		      if(ok)
			if(a.size() == 3)
			  a.replace
			    (2,
			     crypt.decrypted(a.at(2), &ok));

		      if(ok)
			{
			  list = a;
			  page = qobject_cast<spoton_buzzpage *>
			    (m_ui.buzzTab->widget(i));
			}

		      break;
		    }
		}

	      if(page)
		{
		  if(list.size() == 2)
		    {
		      if(page->userStatus(list))
			if(m_ui.tab->currentIndex() != 0)
			  m_sb.buzz->setVisible(true);
		    }
		  else
		    {
		      QByteArray hash;
		      bool ok = true;

		      if(m_crypt)
			hash = spoton_crypt::keyedHash
			  (data,
			   QByteArray(m_crypt->symmetricKey(),
				      m_crypt->symmetricKeyLength()),
			   "sha512", &ok);
		      else
			hash = spoton_crypt::sha512Hash(hash, &ok);

		      if(!ok)
			{
			  hash = spoton_crypt::weakRandomBytes(64);
			  spoton_misc::logError
			    ("spoton::slotReceivedKernelMessage(): "
			     "hash failure. Using random bytes.");
			}

		      page->appendMessage(hash, list);

		      if(m_ui.tab->currentIndex() != 0)
			m_sb.buzz->setVisible(true);
		    }
		}
	    }
	  else if(data.startsWith("message_"))
	    {
	      data.remove(0, strlen("message_"));

	      if(!data.isEmpty())
		{
		  QList<QByteArray> list(data.split('_'));

		  if(list.size() != 3)
		    continue;

		  for(int i = 0; i < list.size(); i++)
		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  QByteArray hash;
		  bool duplicate = false;
		  bool ok = true;

		  if(m_crypt)
		    hash = spoton_crypt::keyedHash
		      (list.at(0),
		       QByteArray(m_crypt->symmetricKey(),
				  m_crypt->symmetricKeyLength()),
		       "sha512", &ok);
		  else
		    hash = spoton_crypt::sha512Hash(list.at(0), &ok);

		  if(!ok)
		    {
		      hash = spoton_crypt::weakRandomBytes(64);
		      spoton_misc::logError
			("spoton::slotReceivedKernelMessage(): "
			 "hash failure. Using random bytes.");
		    }

		  if(m_messagingCache.contains(hash))
		    duplicate = true;
		  else
		    m_messagingCache.insert(hash, 0);

		  if(duplicate)
		    continue;

		  QByteArray name(list.at(1));
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
      spoton_misc::logError("spoton::slotReceivedKernelMessage(): "
			    "unable to detect an EOL in m_kernelSocketData. "
			    "The container is bloated! Purging.");
    }
}

void spoton::slotSharePublicKey(void)
{
  if(!m_crypt)
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
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

  publicKey = m_crypt->publicKey(&ok);

  if(ok)
    signature = m_crypt->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_signatureCrypt->publicKey(&ok);

  if(ok)
    sSignature = m_signatureCrypt->digitalSignature(sPublicKey, &ok);

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
      message.append(QByteArray("messaging").toBase64());
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
	  ("spoton::slotSharePublicKey(): write() failure.");
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QModelIndexList list
	  (m_ui.participants->selectionModel()->selectedRows(1));
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      query.exec(QString("DELETE FROM friends_public_keys WHERE "
				 "OID = %1").arg(data.toString()));
	  }

	spoton_misc::purgeSignatureRelationships(db);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
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

void spoton::highlightKernelPath(void)
{
  QColor color;
  QFileInfo fileInfo(m_ui.kernelPath->text());
  QPalette palette;

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
		    m_settings["gui/acceptPublicizedListeners"]);
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
    ("gui/chatSendMethod", m_settings.value("gui/chatSendMethod").toString());
}

void spoton::slotSharePublicKeyWithParticipant(void)
{
  if(!m_crypt)
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item
	(row, 2); // neighbor_oid

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypt->publicKey(&ok);

  if(ok)
    signature = m_crypt->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_signatureCrypt->publicKey(&ok);

  if(ok)
    sSignature = m_signatureCrypt->digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/nodeName", "unknown").
		      toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      message.append("befriendparticipant_");
      message.append(oid);
      message.append("_");
      message.append(QByteArray("messaging").toBase64());
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
	  ("spoton::slotSharePublicKeyWithParticipant(): write() failure.");
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotViewDocumentation(void)
{
  m_docViewer.show(this);
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
    ("gui/my_status", m_settings.value("gui/my_status").toString());
}

bool spoton::isKernelActive(void) const
{
  return m_ui.pid->text() != "0";
}

void spoton::slotCopyMyPublicKey(void)
{
  if(!m_crypt)
    return;

  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  bool ok = true;

  name = m_settings.value("gui/nodeName", "unknown").toByteArray().
    trimmed();
  mPublicKey = m_crypt->publicKey(&ok);

  if(ok)
    mSignature = m_crypt->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_signatureCrypt->publicKey(&ok);

  if(ok)
    sSignature = m_signatureCrypt->digitalSignature(sPublicKey, &ok);

  if(ok)
    clipboard->setText
      ("K" + QByteArray("messaging").toBase64() + "@" +
       name.toBase64() + "@" +
       mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
       sPublicKey.toBase64() + "@" + sSignature.toBase64());
  else
    clipboard->clear();
}

void spoton::slotPopulateCountries(void)
{
  if(!m_crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "country_inclusion.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_countriesLastModificationTime)
	return;
      else
	m_countriesLastModificationTime = fileInfo.lastModified();
    }
  else
    m_countriesLastModificationTime = QDateTime();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	if(query.exec("SELECT country, accepted FROM country_inclusion"))
	  {
	    QList<QListWidgetItem *> list(m_ui.countries->selectedItems());
	    QString selectedCountry("");
	    int hval = m_ui.countries->horizontalScrollBar()->value();
	    int vval = m_ui.countries->verticalScrollBar()->value();

	    if(!list.isEmpty())
	      selectedCountry = list.at(0)->text();

	    m_ui.countries->clear();

	    QList<QPair<QString, bool> > countries;

	    while(query.next())
	      {
		QString country("");
		bool accepted = true;
		bool ok = true;

		country = m_crypt->decrypted(QByteArray::
					     fromBase64(query.
							value(0).
							toByteArray()),
					     &ok).constData();

		if(ok)
		  accepted = m_crypt->decrypted(QByteArray::
						fromBase64(query.
							   value(1).
							   toByteArray()),
						&ok).toInt();

		if(ok)
		  {
		    QPair<QString, bool> pair(country, accepted);

		    countries.append(pair);
		  }
	      }

	    qSort(countries);
	    disconnect(m_ui.countries,
		       SIGNAL(itemChanged(QListWidgetItem *)),
		       this,
		       SLOT(slotCountryChanged(QListWidgetItem *)));

	    QListWidgetItem *selected = 0;

	    while(!countries.isEmpty())
	      {
		QListWidgetItem *item = 0;
		QPair<QString, bool> pair(countries.takeFirst());

		item = new QListWidgetItem(pair.first);
		item->setFlags
		  (Qt::ItemIsEnabled | Qt::ItemIsSelectable |
		   Qt::ItemIsUserCheckable);

		if(pair.second)
		  item->setCheckState(Qt::Checked);
		else
		  item->setCheckState(Qt::Unchecked);

		QPixmap pixmap(pixmapForCountry(item->text()));

		if(pixmap.isNull())
		  pixmap = QPixmap(":/Flags/unknown.png");

		if(!pixmap.isNull())
		  pixmap = pixmap.scaled(QSize(16, 16), Qt::KeepAspectRatio,
					 Qt::SmoothTransformation);

		if(!pixmap.isNull())
		  item->setIcon(QIcon(pixmap));

		m_ui.countries->addItem(item);

		if(!selectedCountry.isEmpty())
		  if(item->text() == selectedCountry)
		    selected = item;
	      }

	    if(selected)
	      selected->setSelected(true);

	    m_ui.countries->horizontalScrollBar()->setValue(hval);
	    m_ui.countries->verticalScrollBar()->setValue(vval);
	    connect(m_ui.countries,
		    SIGNAL(itemChanged(QListWidgetItem *)),
		    this,
		    SLOT(slotCountryChanged(QListWidgetItem *)));

	    if(focusWidget)
	      focusWidget->setFocus();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotCountryChanged(QListWidgetItem *item)
{
  if(!item)
    return;
  else if(!m_crypt)
    return;

  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE country_inclusion SET accepted = ? "
		      "WHERE country_hash = ?");
	query.bindValue
	  (0, m_crypt->encrypted(QString::number(item->checkState()).
				 toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, m_crypt->keyedHash(item->text().toLatin1(), &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(ok)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE neighbors SET "
			  "status_control = 'disconnected' "
			  "WHERE qt_country_hash = ?");
	    query.bindValue
	      (0,
	       m_crypt->keyedHash(item->text().toLatin1(), &ok).toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("spoton");
    }
}

QPixmap spoton::pixmapForCountry(const QString &country)
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
  else if(country == "Algeria")
    return QPixmap(":/Flags/dz.png");
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
  if(m_ui.addFriendPublicKeyRadio->isChecked())
    {
      if(m_ui.friendInformation->toPlainText().trimmed().isEmpty())
	return;

      QString key(m_ui.friendInformation->toPlainText().trimmed());

      if(!(key.startsWith("K") || key.startsWith("k")))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid key. The key must start with either the letter "
		"K or the letter k."));
	  return;
	}

      key.remove(0, 1);

      QList<QByteArray> list(key.toLatin1().split('@'));

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton::slotAddFriendsKey(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      QByteArray keyType(list.at(0));

      keyType = QByteArray::fromBase64(keyType);

      if(!(keyType == "messaging" || keyType == "url"))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid key type. Expecting 'messaging' or 'url'."));
	  return;
	}

      QByteArray mPublicKey(list.at(2));
      QByteArray mSignature(list.at(3));

      mPublicKey = QByteArray::fromBase64(mPublicKey);
      mSignature = QByteArray::fromBase64(mSignature);

      if(!spoton_crypt::isValidSignature(mPublicKey, mPublicKey,
					 mSignature))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid messaging public key signature."));
	  return;
	}

      QByteArray sPublicKey(list.at(4));
      QByteArray sSignature(list.at(5));

      sPublicKey = QByteArray::fromBase64(sPublicKey);
      sSignature = QByteArray::fromBase64(sSignature);

      if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey,
					 sSignature))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid signature public key signature."));
	  return;
	}

      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    spoton_misc::prepareDatabases();

	    QByteArray name(list.at(1));

	    name = QByteArray::fromBase64(name);

	    if(spoton_misc::saveFriendshipBundle("messaging",
						 name,
						 mPublicKey,
						 sPublicKey,
						 -1,
						 db))
	      if(spoton_misc::saveFriendshipBundle("signature",
						   name,
						   sPublicKey,
						   QByteArray(),
						   -1,
						   db))
		m_ui.friendInformation->selectAll();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("spoton");
    }
  else
    {
      /*
      ** Now we have to perform the inverse of slotCopyFriendshipBundle().
      ** Have fun!
      */

      if(!m_crypt)
	return;
      else if(m_ui.friendInformation->toPlainText().trimmed().isEmpty())
	return;

      QByteArray repleo(m_ui.friendInformation->toPlainText().trimmed().
			toLatin1());

      if(!(repleo.startsWith("R") || repleo.startsWith("r")))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid repleo. The repleo must start with "
		"either the letter R or the letter r."));
	  return;
	}

      repleo.remove(0, 1);

      QList<QByteArray> list(repleo.split('@'));

      if(list.size() != 9)
	{
	  spoton_misc::logError
	    (QString("spoton::slotAddFriendsKey(): "
		     "received irregular data. Expecting 9 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hash;
      QByteArray keyType;
      QByteArray name;
      QByteArray publicKey;
      QByteArray signature;
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;
      bool ok = true;

      symmetricKey = list.value(0);
      symmetricKey = m_crypt->publicKeyDecrypt(symmetricKey, &ok);

      if(!ok)
	return;

      symmetricKeyAlgorithm = list.value(1);
      symmetricKeyAlgorithm = m_crypt->publicKeyDecrypt
	(symmetricKeyAlgorithm, &ok);

      if(!ok)
	return;

      spoton_crypt crypt(symmetricKeyAlgorithm,
			 QString("sha512"),
			 QByteArray(),
			 symmetricKey,
			 0,
			 0,
			 QString(""));

      keyType = crypt.decrypted(list.value(2), &ok);

      if(!ok)
	return;

      if(!(keyType == "messaging" || keyType == "url"))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid key type. Expecting 'messaging' or 'url'."));
	  return;
	}

      name = crypt.decrypted(list.value(3), &ok);

      if(!ok)
	return;

      publicKey = crypt.decrypted(list.value(4), &ok);

      if(!ok)
	return;

      signature = crypt.decrypted(list.value(5), &ok);

      if(!ok)
	return;

      if(!spoton_crypt::isValidSignature(publicKey, publicKey,
					 signature))
	{
	  QMessageBox::critical
	    (this, tr("Spot-On: Error"),
	     tr("Invalid signature."));
	  return;
	}

      QByteArray sPublicKey(list.at(6));

      sPublicKey = crypt.decrypted(sPublicKey, &ok);

      if(!ok)
	return;

      QByteArray sSignature(list.at(7));

      sSignature = crypt.decrypted(sSignature, &ok);

      if(!ok)
	return;

      hash = list.value(8);

      QByteArray computedHash
	(crypt.keyedHash(list.value(3) +
			 list.value(4) +
			 list.value(5) +
			 list.value(6) +
			 list.value(7), &ok));

      if(!ok)
	return;

      if(computedHash == hash)
	{
	  {
	    QSqlDatabase db = QSqlDatabase::addDatabase
	      ("QSQLITE", "spoton");

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() +
	       "friends_public_keys.db");

	    if(db.open())
	      {
		spoton_misc::prepareDatabases();

		if(spoton_misc::saveFriendshipBundle(keyType,
						     name,
						     publicKey,
						     sPublicKey,
						     -1,
						     db))
		  if(spoton_misc::saveFriendshipBundle("signature",
						       name,
						       sPublicKey,
						       QByteArray(),
						       -1,
						       db))
		    m_ui.friendInformation->selectAll();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase("spoton");
	}
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
		"data will be lost."));

  if(mb.exec() != QMessageBox::Yes)
    return;

  slotDeactivateKernel();

  QStringList list;

  list << "country_inclusion.db"
       << "email.db"
       << "error_log.dat"
       << "friends_public_keys.db"
       << "idiotes.db"
       << "kernel.db"
       << "listeners.db"
       << "neighbors.db"
       << "shared.db";

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

  if(!m_crypt)
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
  ** 4. Compute a keyed hash of S and T using the symmetric key.
  ** 5. Encrypt the keyed hash with the symmetric key.
  */

  QString neighborOid("");
  QByteArray gemini;
  QByteArray publicKey;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm;

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     symmetricKeyAlgorithm,
				     neighborOid,
				     oid,
				     m_crypt);

  if(publicKey.isEmpty() ||
     symmetricKey.isEmpty() || symmetricKeyAlgorithm.isEmpty())
    {
      clipboard->clear();
      return;
    }

  QByteArray data;
  bool ok = true;

  data.append
    (spoton_crypt::publicKeyEncrypt(symmetricKey, publicKey, &ok).
     toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append
    (spoton_crypt::publicKeyEncrypt(symmetricKeyAlgorithm, publicKey, &ok).
     toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myName;
  QList<QByteArray> list;
  spoton_crypt crypt(symmetricKeyAlgorithm,
		     QString("sha512"),
		     QByteArray(),
		     symmetricKey,
		     0,
		     0,
		     QString(""));

  data.append(crypt.encrypted("messaging", &ok).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  myName = m_settings.value("gui/nodeName", "unknown").toByteArray().
    trimmed();

  if(myName.isEmpty())
    myName = "unknown";

  list.append(crypt.encrypted(myName, &ok));
  data.append(list.at(0).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myPublicKey(m_crypt->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  list.append(crypt.encrypted(myPublicKey, &ok));
  data.append(list.at(1).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySignature(m_crypt->digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  list.append(crypt.encrypted(mySignature, &ok));
  data.append(list.at(2).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySPublicKey(m_signatureCrypt->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  list.append(crypt.encrypted(mySPublicKey, &ok));
  data.append(list.at(3).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySSignature
    (m_signatureCrypt->digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  list.append(crypt.encrypted(mySSignature, &ok));
  data.append(list.at(4).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray hash(crypt.keyedHash(list.at(0) +
				  list.at(1) +
				  list.at(2) +
				  list.at(3) +
				  list.at(4), &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append(hash.toBase64());
  clipboard->setText("R" + data);
}

Ui_spoton_mainwindow spoton::ui(void) const
{
  return m_ui;
}

void spoton::slotSendMail(void)
{
  if(!m_crypt)
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

  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QModelIndexList list;
	QStringList names;
	QStringList oids;
	QStringList publicKeyHashes;

	list = m_ui.emailParticipants->selectionModel()->selectedRows(0);

	while(!list.isEmpty())
	  names.append(list.takeFirst().data().toString());

	list = m_ui.emailParticipants->selectionModel()->selectedRows(1);

	while(!list.isEmpty())
	  oids.append(list.takeFirst().data().toString());

	list = m_ui.emailParticipants->selectionModel()->selectedRows(2);

	while(!list.isEmpty())
	  publicKeyHashes.append(list.takeFirst().data().toString());

	while(!oids.isEmpty())
	  {
	    QByteArray goldbug
	      (m_ui.goldbug->text().trimmed().toUtf8());
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
	      (0, m_crypt->encrypted(now.toString(Qt::ISODate).
				     toLatin1(), &ok).toBase64());
	    query.bindValue(1, 1); // Sent Folder

	    if(ok)
	      query.bindValue
		(2, m_crypt->encrypted(goldbug, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, m_crypt->keyedHash(now.toString().toLatin1() +
				       message + subject, &ok).toBase64());

	    if(ok)
	      query.bindValue(4, m_crypt->encrypted(message, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5, m_crypt->encrypted(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(6, m_crypt->encrypted(names.takeFirst().toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(7, publicKeyHash.toBase64());

	    if(ok)
	      query.bindValue
		(8, m_crypt->encrypted(tr("Queued").toUtf8(),
				       &ok).toBase64());

	    if(ok)
	      query.bindValue
		(9, m_crypt->encrypted(subject, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(10, m_crypt->encrypted(oid.toLatin1(), &ok).
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

  QSqlDatabase::removeDatabase("spoton");
  m_ui.outgoingSubject->setFocus();
}

void spoton::slotDeleteAllBlockedNeighbors(void)
{
  if(!m_crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique blocked neighbors.
  ** Do remember that remote_ip_address contains encrypted data.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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

	      ip =
		m_crypt->decrypted(QByteArray::fromBase64(query.value(0).
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

  QSqlDatabase::removeDatabase("spoton");
  QApplication::restoreOverrideCursor();
}

void spoton::slotCopyMyURLPublicKey(void)
{
}

void spoton::slotShareURLPublicKey(void)
{
}

void spoton::slotDeleteAllUuids(void)
{
   if(!m_crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique uuids.
  ** Do remember that uuid contains encrypted data.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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

	      uuid =
		m_crypt->decrypted(QByteArray::fromBase64(query.value(0).
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

  QSqlDatabase::removeDatabase("spoton");
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

  if(!m_crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.mail->clearContents();
	m_ui.mail->setRowCount(0);
	m_ui.mail->setSortingEnabled(false);
	m_ui.mailMessage->clear();

	QSqlQuery query(db);
	int row = 0;

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT date, receiver_sender, status, "
			      "subject, goldbug, "
			      "message, message_code, "
			      "receiver_sender_hash, "
			      "OID FROM folders WHERE "
			      "folder_index = %1").
		      arg(m_ui.folder->currentIndex())))
	  while(query.next())
	    {
	      QString goldbug("");
	      bool ok = true;

	      goldbug = m_crypt->
		decrypted(QByteArray::
			  fromBase64(query.
				     value(4).
				     toByteArray()),
			  &ok).constData();

	      if(goldbug.isEmpty())
		goldbug = "0";

	      for(int i = 0; i < query.record().count(); i++)
		{
		  bool ok = true;
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
			    item = new QTableWidgetItem
			      (QString::
			       fromUtf8(m_crypt->
					decrypted(QByteArray::
						  fromBase64(query.
							     value(i).
							     toByteArray()),
						  &ok).constData()));
			  else
			    item = new QTableWidgetItem("#####");
			}
		      else
			{
			  if(goldbug == "0")
			    item = new QTableWidgetItem
			      (m_crypt->decrypted(QByteArray::
						  fromBase64(query.
							     value(i).
							     toByteArray()),
						  &ok).constData());
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

	m_ui.mail->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  QApplication::restoreOverrideCursor();
}

void spoton::slotRefreshPostOffice(void)
{
  if(!m_crypt)
    return;
  else if(m_ui.mailTab->currentIndex() != 2)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.postoffice->clearContents();
	m_ui.postoffice->setRowCount(0);
	m_ui.postoffice->setSortingEnabled(false);

	QSqlQuery query(db);
	int row = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT date_received, "
		      "message_bundle, recipient_hash "
		      "FROM post_office"))
	  while(query.next())
	    for(int i = 0; i < query.record().count(); i++)
	      {
		bool ok = true;
		QTableWidgetItem *item = 0;

		if(i == 0)
		  {
		    row += 1;
		    m_ui.postoffice->setRowCount(row);
		  }

		if(i == 0)
		  item = new QTableWidgetItem
		    (m_crypt->decrypted(QByteArray::
					fromBase64(query.
						   value(i).
						   toByteArray()),
					&ok).constData());
		else if(i == 1)
		  {
		    QByteArray bytes
		      (m_crypt->decrypted(QByteArray::
					  fromBase64(query.
						     value(i).
						     toByteArray()),
					  &ok));

		    item = new QTableWidgetItem
		      (QString::number(bytes.size()));
		  }
		else
		  item = new QTableWidgetItem(query.value(i).toString());

		item->setFlags
		  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		m_ui.postoffice->setItem(row - 1, i, item);
	      }

	m_ui.postoffice->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
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
	   QLineEdit::Password, QString(""), &ok);

	if(!ok)
	  return;

	int rc = applyGoldbugToInboxLetter(goldbug.toUtf8(), row);

	if(rc == APPLY_GOLDBUG_TO_INBOX_ERROR_CORRUPT_MESSAGE_CODE)
	  {
	    QMessageBox::critical(this, tr("Spot-On: Error"),
				  tr("The message's code is incorrect."));
	    return;
	  }
	else if(rc == APPLY_GOLDBUG_TO_INBOX_ERROR_GENERAL)
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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

		if(m_crypt)
		  query.bindValue
		    (0, m_crypt->encrypted(tr("Deleted").toUtf8(), &ok).
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

  QSqlDatabase::removeDatabase("spoton");
  slotRefreshMail();
}

void spoton::slotGeminiChanged(QTableWidgetItem *item)
{
  if(!item)
    return;
  else if(item->column() != 5) // Gemini
    return;
  else if(!m_ui.participants->item(item->row(), 1))
    return;

  saveGemini(item->text().toUtf8(), // Gemini
	     m_ui.participants->item(item->row(), 1)->text()); // OID
}

void spoton::slotGenerateGeminiInChat(void)
{
  if(!m_crypt)
    return;

  QModelIndexList list
    (m_ui.participants->selectionModel()->selectedRows(1));

  while(!list.isEmpty())
    {
      QTableWidgetItem *item1 =
	m_ui.participants->item(list.first().row(), 1); // OID
      QTableWidgetItem *item2 =
	m_ui.participants->item(list.first().row(), 5); // Gemini

      list.takeFirst();

      if(!item1 || !item2)
	continue;

      QByteArray gemini
	(spoton_crypt::
	 strongRandomBytes(spoton_crypt::cipherKeyLength("aes256")));

      if(saveGemini(gemini.toBase64(), item1->text()))
	{
	  m_ui.participants->blockSignals(true);
	  item2->setText(gemini.toBase64());
	  m_ui.participants->blockSignals(false);
	}
    }
}

bool spoton::saveGemini(const QByteArray &gemini,
			const QString &oid)
{
  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_save_gemini"); /*
					 ** We need a special database
					 ** name. Please see itemChanged()
					 ** documentation.
					 */

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ? WHERE OID = ?");

	if(gemini.isNull())
	  query.bindValue(0, QVariant(QVariant::ByteArray));
	else
	  {
	    if(m_crypt)
	      query.bindValue(0, m_crypt->encrypted(gemini, &ok).toBase64());
	    else
	      query.bindValue(0, QVariant(QVariant::ByteArray));
	  }

	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_save_gemini");
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM folders WHERE folder_index = 2");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

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
  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    {
      QByteArray message("retrievemail\n");

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  ("spoton::slotRetrieveMail(): write() failure.");
      else
	{
	  m_kernelSocket.flush();
	  m_ui.retrieveMail->setEnabled(false);
	  QTimer::singleShot
	    (5000, this, SLOT(slotEnableRetrieveMail(void)));
	}
    }
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
  if(!m_crypt)
    return false;

  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE folders SET status = ? WHERE "
		      "OID = ?");
	query.bindValue
	  (0, m_crypt->encrypted(status.toUtf8(), &ok).toBase64());
	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
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
  ** Kernel, listeners, and neighbors icons are prepared elsewhere.
  */

  // Generic

  m_ui.action_Documentation->setIcon
    (QIcon(QString(":/%1/documentation.png").arg(iconSet)));
  m_ui.action_Log_Viewer->setIcon
    (QIcon(QString(":/%1/information.png").arg(iconSet)));

  QStringList list;

  // Tab Icons

  list << "buzz.png" << "chat.png" << "email.png" << "add-listener.png"
       << "neighbors.png" << "search.png" << "settings.png" << "urls.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.tab->setTabIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  // Status

  m_sb.buzz->setIcon(QIcon(QString(":/%1/buzz.png").arg(iconSet)));
  m_sb.chat->setIcon(QIcon(QString(":/%1/chat.png").arg(iconSet)));
  m_sb.email->setIcon(QIcon(QString(":/%1/email.png").arg(iconSet)));
  m_sb.errorlog->setIcon(QIcon(QString(":/%1/information.png").arg(iconSet)));

  // Buzz

  m_ui.join->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.saveBuzzName->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));

  // Chat

  m_ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
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

  // Neighbors

  m_ui.toolButtonCopytoClipboard->setIcon
    (QIcon(QString(":/%1/copy.png").arg(iconSet)));
  m_ui.toolButtonMakeFriends->setIcon
    (QIcon(QString(":/%1/share.png").arg(iconSet)));
  m_ui.addNeighbor->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.addFriend->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.clearFriend->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));

  // Search

  m_ui.deleteURL->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.modifyURL->setIcon(QIcon(QString(":/%1/modify.png").arg(iconSet)));
  m_ui.searchURL->setIcon(QIcon(QString(":/%1/search.png").arg(iconSet)));

  // Listeners

  m_ui.addListener->setIcon(QIcon(QString(":/%1/add-listener.png").
				  arg(iconSet)));

  // Settings

  m_ui.activateKernel->setIcon
    (QIcon(QString(":/%1/activate.png").arg(iconSet)));
  m_ui.deactivateKernel->setIcon
    (QIcon(QString(":/%1/deactivate.png").arg(iconSet)));
  m_ui.setPassphrase->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_ui.resetSpotOn->setIcon(QIcon(QString(":/%1/refresh.png").arg(iconSet)));

  // URLs

  m_ui.addDLDistiller->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.delDLDistiller->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.addULDistiller->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.delULDistiller->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (0, QIcon(QString(":/%1/down.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (1, QIcon(QString(":/%1/up.png").arg(iconSet)));

  // Login

  m_ui.passphraseButton->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();
  emit iconsChanged();
}

int spoton::applyGoldbugToInboxLetter(const QByteArray &goldbug,
				      const int row)
{
  if(!m_crypt)
    return APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY;

  QTableWidgetItem *item = m_ui.mail->item
    (row, m_ui.mail->columnCount() - 1); // OID

  if(!item)
    return APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY;

  QString oid(item->text());
  bool ok = true;
  int rc = 0;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if((ok = db.open()))
      {
	QList<QByteArray> list;
	QSqlQuery query(db);

	query.prepare("SELECT date, message, message_code, "
		      "receiver_sender, receiver_sender_hash, "
		      "subject FROM folders "
		      "WHERE OID = ?");
	query.bindValue(0, oid);

	if((ok = query.exec()))
	  if((ok = query.next()))
	    for(int i = 0; i < query.record().count(); i++)
	      {
		if(i == 4)
		  list.append
		    (QByteArray::fromBase64(query.value(i).
					    toByteArray()));
		else
		  list.append
		    (m_crypt->decrypted(QByteArray::
					fromBase64(query.
						   value(i).
						   toByteArray()),
					&ok));

		if(!ok)
		  break;
	      }

	if(ok)
	  {
	    QByteArray computedMessageCode;
	    spoton_crypt crypt("aes256",
			       QString("sha512"),
			       QByteArray(),
			       goldbug,
			       0,
			       0,
			       QString(""));

	    computedMessageCode =
	      crypt.keyedHash(list.value(3) + // receiver_sender
			      list.value(5) + // subject
			      list.value(1),  // message
			      &ok);

	    if(computedMessageCode != list.value(2))
	      {
		rc = APPLY_GOLDBUG_TO_INBOX_ERROR_CORRUPT_MESSAGE_CODE;
		spoton_misc::logError
		  ("spoton::applyGoldbugToInboxLetter(): "
		   "computed message code does "
		   "not match provided code.");
		ok = false;
	      }

	    if(ok)
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

	    query.prepare("UPDATE folders SET "
			  "goldbug = ?, "
			  "hash = ?, "
			  "message = ?, "
			  "message_code = ?, "
			  "receiver_sender = ?, "
			  "subject = ? "
			  "WHERE OID = ?");

	    if(ok)
	      query.bindValue
		(0, m_crypt->
		 encrypted(QString::number(0).toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(1, m_crypt->keyedHash(list.value(1) + list.value(4), &ok).
		 toBase64());

	    if(!list.value(1).isEmpty())
	      if(ok)
		query.bindValue
		  (2, m_crypt->encrypted(list.value(1), &ok).toBase64());

	    if(!list.value(2).isEmpty())
	      if(ok)
		query.bindValue
		  (3, m_crypt->encrypted(list.value(2), &ok).toBase64());

	    if(!list.value(3).isEmpty())
	      if(ok)
		query.bindValue
		  (4, m_crypt->encrypted(list.value(3), &ok).toBase64());

	    if(!list.value(5).isEmpty())
	      if(ok)
		query.bindValue
		  (5, m_crypt->encrypted(list.value(5), &ok).toBase64());

	    query.bindValue(6, oid);

	    if(ok)
	      ok = query.exec();
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

  QSqlDatabase::removeDatabase("spoton");

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
	item(i, 2); // public_key_hash

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
  if(!isKernelActive())
    return;

  QByteArray message;

  message.append("publicizealllistenersplaintext\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      ("spoton::slotPublicizeAllListenersPlaintext(): write() failure.");
  else
    m_kernelSocket.flush();
}

void spoton::slotPublicizeListenerPlaintext(void)
{
  if(!isKernelActive())
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
      ("spoton::slotPublicizeListenerPlaintext(): write() failure.");
  else
    m_kernelSocket.flush();
}

void spoton::slotCongestionControl(bool state)
{
  m_settings["gui/enableCongestionControl"] = state;

  QSettings settings;

  settings.setValue("gui/enableCongestionControl", state);
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

void spoton::slotPublishedKeySizeChanged(const QString &text)
{
  m_settings["gui/publishedKeySize"] = text.toInt();

  QSettings settings;

  settings.setValue
    ("gui/publishedKeySize",
     m_settings.value("gui/publishedKeySize").toInt());
}

void spoton::slotJoinBuzzChannel(void)
{
  QString channel(m_ui.channel->text().trimmed());

  if(channel.isEmpty())
    return;

  bool found = false;

  for(int i = 0; i < m_ui.buzzTab->count(); i++)
    if(channel == m_ui.buzzTab->tabText(i))
      {
	found = true;
	m_ui.buzzTab->setCurrentIndex(i);
	break;
      }

  if(found)
    return;

  QByteArray id(spoton_crypt::strongRandomBytes(128).toBase64());

  m_ui.channel->clear();

  spoton_buzzpage *page = new spoton_buzzpage
    (&m_kernelSocket, channel.toLatin1(), id, this); /*
						     ** Should channel
						     ** names be
						     ** converted to
						     ** UTF-8?
						     */

  connect(&m_buzzStatusTimer,
	  SIGNAL(timeout(void)),
	  page,
	  SLOT(slotSendStatus(void)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  page,
	  SLOT(slotSetIcons(void)));
  m_ui.buzzTab->addTab(page, channel);
  m_ui.buzzTab->setCurrentIndex(m_ui.buzzTab->count() - 1);
}

void spoton::slotCloseBuzzTab(int index)
{
  int count = 0;
  spoton_buzzpage *page = qobject_cast<spoton_buzzpage *>
    (m_ui.buzzTab->widget(index));

  count = m_ui.buzzTab->count();

  if(page)
    {
      count -= 1;
      page->deleteLater();
    }

  if(!count)
    m_buzzStatusTimer.stop();
}
