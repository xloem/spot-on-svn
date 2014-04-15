/*
** Copyright (c) 2011 - 10^10^10 Alexis Megas
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

  m_ui.institutions->clearContents();
  m_ui.institutions->setRowCount(0);
  m_ui.institutions->setSortingEnabled(false);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
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
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  m_ui.institutions->setSortingEnabled(true);
}

void spoton::slotAddInstitution(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QString name("");
  QString postalAddress("");

  if(m_ui.addInstitutionCheckBox->isChecked())
    {
      QStringList list(m_ui.addInstitutionLineEdit->text().
		       trimmed().remove("magnet:?").split("&"));

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

	      int index = m_ui.institutionNameType->findText(str);

	      if(index > -1)
		m_ui.institutionNameType->setCurrentIndex(index);
	    }
	  else if(str.startsWith("pa="))
	    {
	      str.remove(0, 3);
	      postalAddress = str;
	    }
	  else if(str.startsWith("ht="))
	    {
	      str.remove(0, 3);

	      int index = m_ui.institutionPostalAddressType->findText(str);

	      if(index > -1)
		m_ui.institutionPostalAddressType->setCurrentIndex(index);
	    }
	}
    }
  else
    {
      name = m_ui.institutionName->text().trimmed();
      postalAddress = m_ui.institutionPostalAddress->text().trimmed();
    }

  if(name.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Please provide an institution name."));
      return;
    }

  if(postalAddress.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
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
	  (0, crypt->encryptedThenHashed(m_ui.institutionNameType->
					 currentText().toLatin1(),
					 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed(m_ui.institutionPostalAddressType->
				 currentText().toLatin1(),
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
      m_ui.addInstitutionLineEdit->clear();
      m_ui.institutionName->clear();
      m_ui.institutionNameType->setCurrentIndex(0);
      m_ui.institutionPostalAddress->clear();
      m_ui.institutionPostalAddressType->setCurrentIndex(0);
      refreshInstitutions();
    }
  else
    QMessageBox::critical(this, tr("Spot-On: Error"),
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
  Q_UNUSED(state);
}
