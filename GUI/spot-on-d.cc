/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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
#include "spot-on-defines.h"
#include "ui_adaptiveechoprompt.h"

void spoton::slotDiscoverMissingLinks(void)
{
  if(!m_starbeamAnalyzer)
    return;

  QString fileName("");
  QString oid("");
  QString pulseSize("");
  QString totalSize("");
  int row = -1;

  if((row = m_ui.received->currentRow()) >= 0)
    {
      QTableWidgetItem *item = 0;

      item = m_ui.received->item(row, 3); // File

      if(item)
	fileName = item->text();

      item = m_ui.received->item(row, 1); // Pulse Size

      if(item)
	pulseSize = item->text();

      item = m_ui.received->item(row, 2); // Total Size

      if(item)
	totalSize = item->text();

      item = m_ui.received->item
	(row, m_ui.received->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  m_starbeamAnalyzer->add(fileName, oid, pulseSize, totalSize);
  m_starbeamAnalyzer->show(this);
}

void spoton::slotShowStarBeamAnalyzer(void)
{
  if(m_starbeamAnalyzer)
    m_starbeamAnalyzer->show(this);
}

void spoton::slotDemagnetizeMissingLinks(void)
{
  QStringList list
    (m_ui.missingLinks->text().trimmed().remove("magnet:?").split("&"));

  while(!list.isEmpty())
    {
      QString str(list.takeFirst().trimmed());

      if(str.startsWith("fn="))
	{
	  str.remove(0, 3);
	  m_ui.transmittedFile->setText(str);
	}
      else if(str.startsWith("ps="))
	{
	  str.remove(0, 3);
	  m_ui.pulseSize->setValue(str.toInt());
	}
      else
	break;
    }
}

void spoton::slotUpdateChatWindows(void)
{
  /*
  ** Remove m_chatWindows entries that are invalid.
  */

  QMutableHashIterator<QString, QPointer<spoton_chatwindow> > it
    (m_chatWindows);

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	it.remove();
    }

  /*
  ** Update existing chat windows.
  */

  QStringList list;

  if(!m_chatWindows.isEmpty())
    for(int i = 0; i < m_ui.participants->rowCount(); i++)
      {
	QIcon icon;
	QString name("");
	QString oid("");
	QString publicKeyHash("");
	QTableWidgetItem *item = 0;

	item = m_ui.participants->item(i, 0);

	if(item)
	  {
	    icon = item->icon();
	    name = item->text();
	  }

	item = m_ui.participants->item(i, 1);

	if(item)
	  oid = item->text();

	if(!m_chatWindows.contains(oid))
	  m_chatWindows.remove(oid);

	emit statusChanged(icon, name, oid);
	item = m_ui.participants->item(i, 3);

	if(item)
	  publicKeyHash = item->text();

	if(!publicKeyHash.isEmpty())
	  list.append(publicKeyHash);
      }

  /*
  ** Remove chat windows that do not have corresponding participants
  ** entries.
  */

  it.toFront();

  while(it.hasNext())
    {
      it.next();

      if(!list.contains(it.key()))
	{
	  if(it.value())
	    it.value()->deleteLater();

	  it.remove();
	}
    }
}

void spoton::refreshInstitutions(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.institutions->clearContents();
	m_ui.institutions->setRowCount(0);
	m_ui.institutions->setSortingEnabled(false);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, hash_type, "
		      "name, postal_address FROM institutions"))
	  while(query.next())
	    {
	      m_ui.institutions->setRowCount
		(m_ui.institutions->rowCount() + 1);

	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      bool ok = true;

	      cipherType = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		hashType = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		name = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		postalAddress = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      QTableWidgetItem *item = 0;

	      if(ok)
		item = new QTableWidgetItem(name.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 0, item);

	      if(ok)
		item = new QTableWidgetItem(cipherType.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 1, item);

	      if(ok)
		item = new QTableWidgetItem(postalAddress.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 2, item);

	      if(ok)
		item = new QTableWidgetItem(hashType.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 3, item);
	    }

	m_ui.institutions->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotAddInstitution(const QString &text)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QString name("");
  QString nameType("");
  QString postalAddress("");
  QString postalAddressType("");

  if(m_ui.addInstitutionCheckBox->isChecked() || !text.isEmpty())
    {
      QStringList list;

      if(text.isEmpty())
	list = m_ui.addInstitutionLineEdit->text().
	  trimmed().remove("magnet:?").split("&");
      else
	list = text.trimmed().remove("magnet:?").split("&");

      for(int i = 0; i < list.size(); i++)
	{
	  QString str(list.at(i).trimmed());

	  if(str.startsWith("in="))
	    {
	      str.remove(0, 3);
	      name = str;
	    }
	  else if(str.startsWith("ct="))
	    {
	      str.remove(0, 3);
	      nameType = str;
	    }
	  else if(str.startsWith("pa="))
	    {
	      str.remove(0, 3);
	      postalAddress = str;
	    }
	  else if(str.startsWith("ht="))
	    {
	      str.remove(0, 3);
	      postalAddressType = str;
	    }
	}
    }
  else
    {
      name = m_ui.institutionName->text().trimmed();
      nameType = m_ui.institutionNameType->currentText();
      postalAddress = m_ui.institutionPostalAddress->text().trimmed();
      postalAddressType = m_ui.institutionPostalAddressType->currentText();
    }

  if(name.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide an institution name."));
      return;
    }

  if(postalAddress.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide an institution "
			       "postal address."));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO institutions "
	   "(cipher_type, hash_type, hash, name, postal_address) "
	   "VALUES (?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(nameType.toLatin1(),
					 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed(postalAddressType.toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(name.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->encryptedThenHashed(name.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->
	     encryptedThenHashed(postalAddress.toLatin1(), &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      if(text.isEmpty())
	{
	  m_ui.addInstitutionLineEdit->clear();
	  m_ui.institutionName->clear();
	  m_ui.institutionNameType->setCurrentIndex(0);
	  m_ui.institutionPostalAddress->clear();
	  m_ui.institutionPostalAddressType->setCurrentIndex(0);
	}

      refreshInstitutions();
    }
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to record the institution."));
}

void spoton::slotDeleteInstitution(void)
{
  QModelIndexList list
    (m_ui.institutions->selectionModel()->selectedRows(0)); // Name

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
	bool ok = true;

	query.prepare("DELETE FROM institutions WHERE hash = ?");

	if(m_crypts.value("email", 0))
	  query.bindValue
	    (0, m_crypts.value("email")->
	     keyedHash(list.value(0).data().toString().toLatin1(), &ok).
	     toBase64());
	else
	  ok = false;

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  refreshInstitutions();
}

void spoton::slotCopyInstitution(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  int row = -1;

  if((row = m_ui.institutions->currentRow()) >= 0)
    {
      QTableWidgetItem *item1 = m_ui.institutions->item(row, 0);
      QTableWidgetItem *item2 = m_ui.institutions->item(row, 1);
      QTableWidgetItem *item3 = m_ui.institutions->item(row, 2);
      QTableWidgetItem *item4 = m_ui.institutions->item(row, 3);

      if(item1 && item2 && item3 && item4)
	{
	  QString magnet(QString("magnet:?"
				 "in=%1&"
				 "ct=%2&"
				 "pa=%3&"
				 "ht=%4&"
				 "xt=urn:institution").
			 arg(item1->text()).
			 arg(item2->text()).
			 arg(item3->text()).
			 arg(item4->text()));

	  clipboard->setText(magnet);
	}
    }
}

void spoton::slotShowMinimalDisplay(bool state)
{
#if SPOTON_GOLDBUG == 1
  m_ui.buildInformation->setHidden(state);
  m_ui.label_27->setHidden(state);
  m_ui.passphraseGroupBox->setHidden(state);
  m_ui.scrambler->setHidden(state);
  m_ui.impersonate->setHidden(state);
  m_ui.label_58->setHidden(state);
  m_ui.geoipPath4->setHidden(state);
  m_ui.selectGeoIP4->setHidden(state);
  m_ui.geoipPath6->setHidden(state);
  m_ui.selectGeoIP6->setHidden(state);
  m_ui.label_81->setHidden(state);
  m_ui.pid->setHidden(state);
  m_ui.label_17->setHidden(state);
  m_ui.line_4->setHidden(state);
  m_ui.label_4->setHidden(state);
  m_ui.cipherType->setHidden(state);
  m_ui.hashType->setHidden(state);
  m_ui.iterationCount->setHidden(state);
  m_ui.saltLength->setHidden(state);
  m_ui.label_58->setHidden(state);
  m_ui.label_43->setHidden(state);
  m_ui.sslControlString->setHidden(state);
  m_ui.saveSslControlString->setHidden(state);
  m_ui.label_42->setHidden(state);
  m_ui.label_41->setHidden(state);
  m_ui.label_40->setHidden(state);
  m_ui.label_42->setHidden(state);
  m_ui.label_38->setHidden(state);
  m_ui.ipv4Listener->setHidden(state);
  m_ui.ipv6Listener->setHidden(state);
  m_ui.listenerScopeIdLabel->setHidden(state);
  m_ui.listenerScopeId->setHidden(state);
  m_ui.label_12->setHidden(state);
  m_ui.listenerPort->setHidden(state);
  m_ui.label_15->setHidden(state);
  m_ui.sslListener->setHidden(state);
  m_ui.listenerKeySize->setHidden(state);
  m_ui.listenersEchoMode->setHidden(state);
  m_ui.deleteAllListeners->setHidden(state);
  m_ui.label_28->setHidden(state);
  m_ui.publishedKeySize->setHidden(state);
  m_ui.recordIPAddress->setHidden(state);
  m_ui.permanentCertificate->setHidden(state);
  m_ui.groupBox_5->setHidden(state);
  m_ui.accountsGB->setHidden(state);
  m_ui.listeners->setHidden(state);
  m_ui.label_65->setHidden(state);
  m_ui.listenerTransport->setHidden(state);
  m_ui.label_71->setHidden(state);
  m_ui.listenerOrientation->setHidden(state);
  m_ui.listenersActionMenu->setHidden(state);
  m_ui.listeners->setColumnHidden(2, state);
  m_ui.listeners->setColumnHidden(5, state);
  m_ui.listeners->setColumnHidden(6, state);
  m_ui.listeners->setColumnHidden(9, state);
  m_ui.listeners->setColumnHidden(10, state);
  m_ui.listeners->setColumnHidden(11, state);
  m_ui.proxy->setHidden(state);
  m_ui.neighborKeySize->setHidden(state);
  m_ui.label_13->setHidden(state);
  m_ui.neighborPort->setHidden(state);
  m_ui.neighborScopeIdLabel->setHidden(state);
  m_ui.neighborScopeId->setHidden(state);
  m_ui.ipv4Neighbor->setHidden(state);
  m_ui.ipv6Neighbor->setHidden(state);
  m_ui.dynamicdns->setHidden(state);
  m_ui.neighborsEchoMode->setHidden(state);
  m_ui.addException->setHidden(state);
  m_ui.groupBox_4->setHidden(state);
  m_ui.requireSsl->setHidden(state);
  m_ui.label_32->setHidden(state);
  m_ui.buzzName->setHidden(state);
  m_ui.saveBuzzName->setHidden(state);
  m_ui.clearMessages->setHidden(state);
  m_ui.copyrepleo_chat->setHidden(state);
  m_ui.chatAcceptSigned->setHidden(state);
  m_ui.acceptChatKeys->setHidden(state);
  m_ui.chatSignMessages->setHidden(state);
  m_ui.participants->setColumnHidden(4, state);
  m_ui.participants->setColumnHidden(7, state);
  m_ui.mail->setColumnHidden(0, state);
  m_ui.mail->setColumnHidden(2, state);
  m_ui.label_16->setHidden(state);
  m_ui.emailName->setHidden(state);
  m_ui.saveEmailName->setHidden(state);
  m_ui.saveCopy->setHidden(state);
  m_ui.emailSignMessages->setHidden(state);
  m_ui.line_18->setHidden(state);
  m_ui.postoffice->setHidden(state);
  m_ui.emailAcceptSigned->setHidden(state);
  m_ui.acceptEmailKeys->setHidden(state);
  m_ui.label_79->setHidden(state);
  m_ui.label_80->setHidden(state);
  m_ui.institutionNameType->setHidden(state);
  m_ui.institutionPostalAddressType->setHidden(state);
  m_ui.institutions->setColumnHidden(1, state);
  m_ui.institutions->setColumnHidden(3, state);
  m_ui.etpMagnets->setHidden(state);
  m_ui.label_52->setHidden(state);
  m_ui.label_57->setHidden(state);
  m_ui.etpCipherType->setHidden(state);
  m_ui.etpHashType->setHidden(state);
  m_ui.generate->setHidden(state);
  m_ui.label_60->setHidden(state);
  m_ui.label_69->setHidden(state);
  m_ui.generateNova->setHidden(state);
  m_ui.transmitNova->setHidden(state);
  m_ui.label_54->setHidden(state);
  m_ui.pulseSize->setHidden(state);
  m_ui.magnetsActionMenu->setHidden(state);
  m_ui.missingLinksCheckBox->setHidden(state);
  m_ui.missingLinks->setHidden(state);
  m_ui.demagnetizeMissingLinks->setHidden(state);
#else
  m_sb.errorlog->setHidden(state);
  m_ui.chatSendMethod->setHidden(state);
  m_ui.neighborSummary->setHidden(state);
#endif
}

void spoton::slotSaveMOTD(void)
{
  QString connectionName("");
  QString error("");
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
      error = tr("Invalid listener OID. Please select a listener.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString str(m_ui.motd->toPlainText().trimmed());

	if(str.isEmpty())
	  str = QString("Welcome to %1.").
	    arg(SPOTON_APPLICATION_NAME);

	query.prepare("UPDATE listeners SET motd = ? WHERE OID = ?");
	query.bindValue(0, str);
	query.bindValue(1, oid);

	if(!query.exec())
	  error = tr("Database error. Unable to save the message of the day.");
      }
    else
      error = tr("Unable to open listeners.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
}

void spoton::populateMOTD(const QString &listenerOid)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	m_ui.motd->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT motd FROM listeners "
		      "WHERE OID = ?");
	query.bindValue(0, listenerOid);

	if(query.exec())
	  if(query.next())
	    m_ui.motd->setPlainText(query.value(0).toString());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotChatPopup(void)
{
  QList<QTableWidgetItem *> items(m_ui.participants->selectedItems());

  if(!items.isEmpty() && items.at(0))
    slotParticipantDoubleClicked
      (m_ui.participants->item(items.at(0)->row(), 0));
}

void spoton::slotCommonBuzzChannelsActivated(const QString &text)
{
  repaint();
  m_ui.demagnetize->setText(text);
  demagnetize();
  m_ui.demagnetize->clear();
  m_ui.buzzActions->setCurrentIndex(0);
  disconnect(m_ui.commonBuzzChannels,
	     SIGNAL(activated(const QString &)),
	     this,
	     SLOT(slotCommonBuzzChannelsActivated(const QString &)));
  m_ui.commonBuzzChannels->setCurrentIndex(0);
  connect(m_ui.commonBuzzChannels,
	  SIGNAL(activated(const QString &)),
	  this,
	  SLOT(slotCommonBuzzChannelsActivated(const QString &)));
}

void spoton::slotConnectAllNeighbors(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("UPDATE neighbors SET status_control = 'connected' "
	   "WHERE status_control <> 'deleted' AND "
	   "user_defined = 1");
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDisconnectAllNeighbors(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("UPDATE neighbors SET status_control = 'disconnected' "
	   "WHERE status_control <> 'deleted'");
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotMessagesAnchorClicked(const QUrl &link)
{
  QString type("");

  if(spoton_misc::isValidBuzzMagnet(link.toString().toLatin1()))
    type = "buzz";
  else if(spoton_misc::isValidInstitutionMagnet(link.toString().toLatin1()))
    type = "institution";
  else if(spoton_misc::isValidStarBeamMagnet(link.toString().toLatin1()))
    type = "starbeam";

  if(type.isEmpty())
    return;

  QAction *action = 0;
  QMenu menu(this);

  action = menu.addAction(tr("&Add magnet."),
			  this,
			  SLOT(slotAddMagnet(void)));
  action->setProperty("type", type);
  action->setProperty("url", link);
  menu.exec(QCursor::pos());
}

void spoton::slotAddMagnet(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString().trimmed());
  QUrl url(action->property("url").toUrl());

  if(type == "buzz")
    {
      spoton_crypt *crypt = m_crypts.value("chat", 0);

      if(!crypt)
	{
	  QMessageBox::critical(this, tr("%1: Error").
				arg(SPOTON_APPLICATION_NAME),
				tr("Invalid spoton_crypt object. This is "
				   "a fatal flaw."));
	  return;
	}

      QByteArray channel;
      QByteArray channelSalt;
      QByteArray channelType;
      QByteArray hashKey;
      QByteArray hashType;
      QByteArray iterationCount;
      QStringList list
	(url.toString().trimmed().remove("magnet:?").split("&"));

      while(!list.isEmpty())
	{
	  QString str(list.takeFirst().trimmed());

	  if(str.startsWith("rn="))
	    {
	      str.remove(0, 3);
	      channel = str.toLatin1();
	    }
	  else if(str.startsWith("xf="))
	    {
	      str.remove(0, 3);
	      iterationCount = str.toLatin1();
	    }
	  else if(str.startsWith("xs="))
	    {
	      str.remove(0, 3);
	      channelSalt = str.toLatin1();
	    }
	  else if(str.startsWith("ct="))
	    {
	      str.remove(0, 3);
	      channelType = str.toLatin1();
	    }
	  else if(str.startsWith("hk="))
	    {
	      str.remove(0, 3);
	      hashKey = str.toLatin1();
	    }
	  else if(str.startsWith("ht="))
	    {
	      str.remove(0, 3);
	      hashType = str.toLatin1();
	    }
	  else if(str.startsWith("xt="))
	    {
	    }
	}

      QString connectionName("");
      bool ok = true;

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "buzz_channels.db");

	if(db.open())
	  {
	    QByteArray data;
	    QSqlQuery query(db);

	    data.append(channel.toBase64());
	    data.append("\n");
	    data.append(iterationCount.toBase64());
	    data.append("\n");
	    data.append(channelSalt.toBase64());
	    data.append("\n");
	    data.append(channelType.toBase64());
	    data.append("\n");
	    data.append(hashKey.toBase64());
	    data.append("\n");
	    data.append(hashType.toBase64());
	    data.append("\n");
	    data.append(QByteArray("urn:buzz").toBase64());
	    query.prepare("INSERT OR REPLACE INTO buzz_channels "
			  "(data, data_hash) "
			  "VALUES (?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(data, &ok).toBase64());

	    if(ok)
	      query.bindValue(1, crypt->keyedHash(data, &ok).toBase64());

	    if(ok)
	      ok = query.exec();
	  }
	else
	  ok = false;

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(!ok)
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("An error occurred while attempting to "
				 "save the channel data. Please enable "
				 "logging via the Log Viewer and try again."));
      else
	slotPopulateBuzzFavorites();
    }
  else if(type == "institution")
    slotAddInstitution(url.toString());
  else if(type == "starbeam")
    slotAddEtpMagnet(url.toString());
}

void spoton::slotAddAEToken(void)
{
  QString connectionName("");
  QString error("");
  QString token(m_ui.ae_token->text().trimmed());
  QString type(m_ui.ae_type->currentText());
  bool ok = true;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if(token.isEmpty() || type == "n/a")
    {
      error = tr("Please provide a token and a token type.");
      goto done_label;
    }
  else if(token.length() < 16)
    {
      error = tr("Please provide a token that contains at "
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

	query.prepare
	  ("INSERT OR REPLACE INTO listeners_adaptive_echo_tokens "
	   "(token, "
	   "token_hash, "
	   "token_type) "
	   "VALUES (?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(token.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash((token + type).toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->encryptedThenHashed(type.toLatin1(),
					   &ok).toBase64());

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
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
  else
    {
      m_ui.ae_token->clear();
      m_ui.ae_type->setCurrentIndex(0);
      populateAETokens();
    }
}

void spoton::slotDeleteAEToken(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QList<QTableWidgetItem *> list(m_ui.ae_tokens->selectedItems());

  if(list.size() != 2 || !list.at(0) || !list.at(1))
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please select a token to delete."));
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

	query.prepare("DELETE FROM listeners_adaptive_echo_tokens WHERE "
		      "token_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash((list.at(0)->text() +
				list.at(1)->text()).toLatin1(), &ok).
	   toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateAETokens();
}

void spoton::populateAETokens(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QByteArray bytes1;
	QByteArray bytes2;
	QModelIndexList list;

	list = m_ui.ae_tokens->selectionModel()->selectedRows
	  (0);

	if(!list.isEmpty())
	  bytes1 = list.at(0).data().toByteArray();

	list = m_ui.ae_tokens->selectionModel()->selectedRows
	  (1);

	if(!list.isEmpty())
	  bytes2 = list.at(0).data().toByteArray();

	m_ui.ae_tokens->setSortingEnabled(false);
	m_ui.ae_tokens->clearContents();
	m_ui.ae_tokens->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare
	  ("SELECT token, token_type FROM listeners_adaptive_echo_tokens");

	if(query.exec())
	  while(query.next())
	    {
	      m_ui.ae_tokens->setRowCount(m_ui.ae_tokens->rowCount() + 1);

	      QByteArray token;
	      QByteArray type;
	      bool ok = true;

	      token = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		type = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      QTableWidgetItem *item = 0;

	      if(ok)
		item = new QTableWidgetItem(token.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      m_ui.ae_tokens->setItem
		(m_ui.ae_tokens->rowCount() - 1, 0, item);

	      if(ok)
		item = new QTableWidgetItem(type.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      m_ui.ae_tokens->setItem
		(m_ui.ae_tokens->rowCount() - 1, 1, item);

	      if(token == bytes1 && type == bytes2)
		m_ui.ae_tokens->selectRow
		  (m_ui.ae_tokens->rowCount() - 1);
	    }

	m_ui.ae_tokens->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotResetAETokenInformation(void)
{
  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "ae_token = NULL, "
		      "ae_token_type = NULL "
		      "WHERE OID = ? AND user_defined = 1");
	query.bindValue(0, list.at(0).data());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSetAETokenInformation(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QModelIndexList list;
  QString oid("");

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid neighbor OID. "
			       "Please select a neighbor."));
      return;
    }
  else
    oid = list.at(0).data().toString();

  QStringList types(spoton_crypt::hashTypes());

  if(types.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("The method spoton_crypt::hashTypes() has "
			       "failed. "
			       "This is a fatal flaw."));
      return;
    }

  QDialog dialog(this);
  Ui_adaptiveechoprompt ui;

  dialog.setWindowTitle
    (tr("%1: Adaptive Echo Information").
     arg(SPOTON_APPLICATION_NAME));
  ui.setupUi(&dialog);
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  ui.token_type->addItems(types);

  if(dialog.exec() == QDialog::Accepted)
    {
      QString token(ui.token->text().trimmed());
      QString tokenType(ui.token_type->currentText());

      if(token.length() >= 16)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("UPDATE neighbors SET "
			      "ae_token = ?, "
			      "ae_token_type = ? "
			      "WHERE OID = ? AND user_defined = 1");
		query.bindValue
		  (0, crypt->encryptedThenHashed(token.toLatin1(),
						 &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, crypt->encryptedThenHashed(tokenType.toLatin1(),
						   &ok).toBase64());

		query.bindValue(2, oid);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
      else
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("The token must contain "
				 "at least sixteen characters."));
    }
}

void spoton::joinDefaultBuzzChannel(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Joining a default Buzz channel. "
			  "Please be patient."));
  m_sb.status->repaint();

  int index = m_ui.commonBuzzChannels->findText
    ("Spot-On_Developer_Channel_Key", Qt::MatchContains);

  if(index >= 0)
    slotCommonBuzzChannelsActivated
      (m_ui.commonBuzzChannels->itemText(index));

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
}
