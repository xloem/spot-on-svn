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

extern "C"
{
#include <curl/curl.h>
}

#include "spot-on.h"
#include "spot-on-defines.h"

static QStringList curl_protocols(void)
{
  QStringList list;
  curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);

  for(int i = 0; data->protocols[i] != 0; i++)
    list << QString(data->protocols[i]).toLower();

  return list;
}

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

  QHash<QString, QVariant> hash;
  bool ok = true;

  hash = spoton_misc::poptasticSettings(crypt, &ok);

  if(!ok)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("A failure occurred with "
			       "spoton_misc::poptasticSettings()."));
      return;
    }

  QDialog dialog(this);
  QString connectionName("");
  QStringList protocols(curl_protocols());

  m_poptasticSettingsUi.setupUi(&dialog);
  connect(m_poptasticSettingsUi.testpop3,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestPoptasticPop3Settings(void)));
  connect(m_poptasticSettingsUi.testsmtp,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestPoptasticSmtpSettings(void)));
  dialog.setWindowTitle
    (tr("%1: Poptastic Settings").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif

  if(!protocols.contains("pop3s"))
    {
      m_poptasticSettingsUi.in_ssltls->clear();
      m_poptasticSettingsUi.in_ssltls->addItem(tr("None"));
    }

  if(!protocols.contains("smtps"))
    {
      m_poptasticSettingsUi.out_ssltls->clear();
      m_poptasticSettingsUi.out_ssltls->addItem(tr("None"));
    }

  if(!(protocols.contains("pop3") ||
       protocols.contains("pop3s")))
    {
      m_poptasticSettingsUi.testpop3->setEnabled(false);
      m_poptasticSettingsUi.testpop3->setToolTip
	(tr("Your version of libcURL does not support POP3."));
    }

  if(!(protocols.contains("smtp") ||
       protocols.contains("smtps")))
    {
      m_poptasticSettingsUi.testsmtp->setEnabled(false);
      m_poptasticSettingsUi.testsmtp->setToolTip
	(tr("Your version of libcURL does not support SMTP."));
    }

  if(!hash.isEmpty())
    {
      int index = -1;

      m_poptasticSettingsUi.in_password->setText
	(hash["in_password"].toString());
      m_poptasticSettingsUi.in_server_address->setText
	(hash["in_server_address"].toString());
      m_poptasticSettingsUi.in_server_port->setValue
	(hash["in_server_port"].toInt());
      index = m_poptasticSettingsUi.in_ssltls->findText
	(hash["in_ssltls"].toString());

      if(index >= 0)
	m_poptasticSettingsUi.in_ssltls->setCurrentIndex(index);

      m_poptasticSettingsUi.in_username->setText
	(hash["in_username"].toString());
      m_poptasticSettingsUi.out_password->setText
	(hash["out_password"].toString());
      m_poptasticSettingsUi.out_server_address->setText
	(hash["out_server_address"].toString());
      m_poptasticSettingsUi.out_server_port->setValue
	(hash["out_server_port"].toInt());
      index = m_poptasticSettingsUi.out_ssltls->findText
	(hash["out_ssltls"].toString());

      if(index >= 0)
	m_poptasticSettingsUi.out_ssltls->setCurrentIndex(index);

      m_poptasticSettingsUi.out_username->setText
	(hash["out_username"].toString());
    }

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
	       "(in_authentication, "
	       "in_method, in_password, in_server_address, "
	       "in_server_port, in_ssltls, in_username, "
	       "out_authentication, "
	       "out_method, out_password, out_server_address, "
	       "out_server_port, out_ssltls, out_username) "
	       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, m_poptasticSettingsUi.in_authentication->currentText());
	    query.bindValue
	      (1, m_poptasticSettingsUi.in_method->currentText());
	    query.bindValue
	      (2, crypt->encryptedThenHashed(m_poptasticSettingsUi.
					     in_password->
					     text().trimmed().
					     toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.in_server_address->
				     text().trimmed().
				     toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->
		 encryptedThenHashed(QByteArray::
				     number(m_poptasticSettingsUi.
					    in_server_port->
					    value()), &ok).toBase64());

	    query.bindValue
	      (5, m_poptasticSettingsUi.in_ssltls->currentText());

	    if(ok)
	      query.bindValue
		(6, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.
				     in_username->text().
				     trimmed().toLatin1(), &ok).
		 toBase64());

	    query.bindValue
	      (7, m_poptasticSettingsUi.out_authentication->currentText());
	    query.bindValue
	      (8, m_poptasticSettingsUi.out_method->currentText());

	    if(ok)
	      query.bindValue
		(9, crypt->encryptedThenHashed(m_poptasticSettingsUi.
					       out_password->
					       text().trimmed().
					       toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(10, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.
				     out_server_address->
				     text().trimmed().
				     toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(11, crypt->
		 encryptedThenHashed(QByteArray::
				     number(m_poptasticSettingsUi.
					    out_server_port->
					    value()), &ok).toBase64());

	    query.bindValue
	      (12, m_poptasticSettingsUi.out_ssltls->currentText());

	    if(ok)
	      query.bindValue
		(13, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.
				     out_username->text().
				     trimmed().toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  m_poptasticSettingsUi.in_password->clear();
  m_poptasticSettingsUi.in_server_address->clear();
  m_poptasticSettingsUi.in_server_port->setValue(1);
  m_poptasticSettingsUi.in_username->clear();
  m_poptasticSettingsUi.out_password->clear();
  m_poptasticSettingsUi.out_server_address->clear();
  m_poptasticSettingsUi.out_server_port->setValue(1);
  m_poptasticSettingsUi.out_username->clear();
}

void spoton::slotTestPoptasticPop3Settings(void)
{
  CURL *curl = 0;
  CURLcode res = CURLE_OK;
  bool ok = false;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  curl = curl_easy_init();

  if(curl)
    {
      curl_easy_setopt
	(curl, CURLOPT_PASSWORD,
	 m_poptasticSettingsUi.in_password->text().trimmed().toLatin1().
	 constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 m_poptasticSettingsUi.in_username->text().trimmed().toLatin1().
	 constData());

      QString scheme("");
      int index = m_poptasticSettingsUi.in_ssltls->currentIndex();

      if(index == 1 || index == 2)
	{
	  scheme = QString("pop3s://%1:%2/").
	    arg(m_poptasticSettingsUi.in_server_address->text().trimmed()).
	    arg(m_poptasticSettingsUi.in_server_port->value());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	  if(index == 2)
	    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	}
      else
	scheme = QString("pop3://%1:%2/").
	  arg(m_poptasticSettingsUi.in_server_address->text().trimmed()).
	  arg(m_poptasticSettingsUi.in_server_port->value());

      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
      curl_easy_setopt(curl, CURLOPT_URL, scheme.toLatin1().constData());
      res = curl_easy_perform(curl);

      if(res == CURLE_OK)
	ok = true;

      curl_easy_cleanup(curl);
    }

  QApplication::restoreOverrideCursor();

  if(ok)
    QMessageBox::information(this, tr("%1: Poptastic POP3 Connection Test").
			     arg(SPOTON_APPLICATION_NAME),
			     tr("Test successful!"));
  else
    QMessageBox::critical(this, tr("%1: Poptastic POP3 Connection Test").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Failure!"));
}

void spoton::slotTestPoptasticSmtpSettings(void)
{
  CURL *curl = 0;
  CURLcode res = CURLE_OK;
  bool ok = false;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  curl = curl_easy_init();

  if(curl)
    {
      curl_easy_setopt
	(curl, CURLOPT_PASSWORD,
	 m_poptasticSettingsUi.out_password->text().trimmed().toLatin1().
	 constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 m_poptasticSettingsUi.out_username->text().trimmed().toLatin1().
	 constData());

      QString scheme("");
      int index = m_poptasticSettingsUi.out_ssltls->currentIndex();

      if(index == 1 || index == 2)
	{
	  scheme = QString("smtps://%1:%2/").
	    arg(m_poptasticSettingsUi.out_server_address->text().trimmed()).
	    arg(m_poptasticSettingsUi.out_server_port->value());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	  if(index == 2)
	    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	}
      else
	scheme = QString("smtp://%1:%2/").
	  arg(m_poptasticSettingsUi.out_server_address->text().trimmed()).
	  arg(m_poptasticSettingsUi.out_server_port->value());

      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
      curl_easy_setopt(curl, CURLOPT_URL, scheme.toLatin1().constData());
      res = curl_easy_perform(curl);

      if(res == CURLE_OK)
	ok = true;

      curl_easy_cleanup(curl);
    }

  QApplication::restoreOverrideCursor();

  if(ok)
    QMessageBox::information(this, tr("%1: Poptastic SMTP Connection Test").
			     arg(SPOTON_APPLICATION_NAME),
			     tr("Test successful!"));
  else
    QMessageBox::critical(this, tr("%1: Poptastic SMTP Connection Test").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Failure!"));
}
