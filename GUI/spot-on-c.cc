/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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

void spoton::slotGenerateEtpKeys(int index)
{
  if(m_ui.pairRadio->isChecked())
    {
      if(index == 0)
	{
	  m_ui.etpEncryptionKey->setText
	    (spoton_crypt::
	     strongRandomBytes(m_ui.etpEncryptionKey->maxLength()).
	     toBase64());
	  m_ui.etpMacKey->setText
	    (spoton_crypt::
	     strongRandomBytes(m_ui.etpMacKey->maxLength()).
	     toBase64());
	}
      else if(index == 1)
	m_ui.etpEncryptionKey->setText
	  (spoton_crypt::
	   strongRandomBytes(m_ui.etpEncryptionKey->maxLength()).
	   toBase64());
      else if(index == 2)
	m_ui.etpMacKey->setText
	  (spoton_crypt::
	   strongRandomBytes(m_ui.etpMacKey->maxLength()).
	   toBase64());

      disconnect(m_ui.generate,
		 SIGNAL(activated(int)),
		 this,
		 SLOT(slotGenerateEtpKeys(int)));
      m_ui.generate->setCurrentIndex(0);
      connect(m_ui.generate,
	      SIGNAL(activated(int)),
	      this,
	      SLOT(slotGenerateEtpKeys(int)));
    }
}

void spoton::slotAddEtpMagnet(void)
{
  QString connectionName("");
  QString error("");
  QString magnet("");
  QStringList list;
  bool ok = true;
  int tokens = 0;
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object.");
      goto done_label;
    }

  if(m_ui.magnetRadio->isChecked())
    magnet = m_ui.etpMagnet->text().trimmed();
  else
    magnet = QString("magnet:?"
		     "ct=%1&"
		     "ek=%2&"
		     "ht=%3&"
		     "mk=%4").
      arg(m_ui.etpCipherType->currentText()).
      arg(m_ui.etpEncryptionKey->text().trimmed()).
      arg(m_ui.etpHashType->currentText()).
      arg(m_ui.etpMacKey->text().trimmed());

  /*
  ** Validate the magnet.
  */

  list = magnet.remove("magnet:?").split('&');

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str.startsWith("ct="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("ek="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("ht="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("mk="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
    }

  if(tokens != 4)
    error = tr("Invalid magnet.");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "etp_magnets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR RPLACE INTO "
		      "etp_magnets "
		      "(magnet, magnet_hash) "
		      "VALUES (?, ?)");
	query.bindValue(0, s_crypt->encrypted(magnet.toLatin1(),
					      &ok).toBase64());

	if(ok)
	  query.bindValue(1, s_crypt->keyedHash(magnet.toLatin1(),
						&ok).toBase64());
    
	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error occurred.");

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
}
