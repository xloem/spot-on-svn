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
#include "ui_poptasticsettings.h"

void spoton::slotConfigurePoptastic(void)
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

  QDialog dialog(this);
  QString connectionName("");
  Ui_poptasticsettings ui;

  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: Poptastic Settings").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "poptastic.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare
	      ("INSERT INTO poptastic "
	       "(in_authentication, in_extension, "
	       "in_method, in_password, in_server_address, "
	       "in_server_port, in_username, "
	       "out_authentication, out_extension, "
	       "out_method, out_password, out_server_address, "
	       "out_server_port, out_username) "
	       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue(0, ui.in_authentication->currentText());
	    query.bindValue(1, ui.in_extension->currentText());
	    query.bindValue(2, ui.in_method->currentText());
	    query.bindValue
	      (3, crypt->encryptedThenHashed(ui.in_password->
					     text().trimmed().
					     toUtf8(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->encryptedThenHashed(ui.in_server_address->
					       text().trimmed().
					       toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5, crypt->
		 encryptedThenHashed(QByteArray::
				     number(ui.in_server_port->
					    value()), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(6, crypt->encryptedThenHashed(ui.in_username->text().
					       trimmed().toUtf8(), &ok).
		 toBase64());

	    query.bindValue(7, ui.out_authentication->currentText());
	    query.bindValue(8, ui.out_extension->currentText());
	    query.bindValue(9, ui.out_method->currentText());

	    if(ok)
	      query.bindValue
		(10, crypt->encryptedThenHashed(ui.out_password->
						text().trimmed().
						toUtf8(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(11, crypt->encryptedThenHashed(ui.out_server_address->
						text().trimmed().
						toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(12, crypt->
		 encryptedThenHashed(QByteArray::
				     number(ui.out_server_port->
					    value()), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(13, crypt->encryptedThenHashed(ui.out_username->text().
						trimmed().toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}
