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

#include <QThread>

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

  QString connectionName("");
  QStringList protocols(curl_protocols());

  connect(m_poptasticSettingsUi.buttonBox->button(QDialogButtonBox::Reset),
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPoptasticSettingsReset(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticSettingsUi.capath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetCAPath(void)));
  connect(m_ui.passphrase2,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_poptasticSettingsUi.selectcapath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectCAPath(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticSettingsUi.proxy,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotPoptasticSettingsReset(bool)),
	  Qt::UniqueConnection);
  connect(m_poptasticSettingsUi.testpop3,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestPoptasticPop3Settings(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticSettingsUi.testsmtp,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestPoptasticSmtpSettings(void)),
	  Qt::UniqueConnection);
  m_poptasticDialog->setWindowTitle
    (tr("%1: Poptastic Settings").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
  m_poptasticDialog->setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  m_poptasticSettingsUi.capath->setText
    (m_settings.value("gui/poptasticCAPath", "").toString());
  m_poptasticSettingsUi.poptasticRefresh->setValue
    (m_settings.value("gui/poptasticRefreshInterval", 5.00).toDouble());

  if(m_settings.value("gui/disablePop3", false).toBool())
    m_poptasticSettingsUi.in_method->setCurrentIndex(0);
  else
    m_poptasticSettingsUi.in_method->setCurrentIndex(2);

  if(m_settings.value("gui/disableSmtp", false).toBool())
    m_poptasticSettingsUi.out_method->setCurrentIndex(0);
  else
    m_poptasticSettingsUi.out_method->setCurrentIndex(1);

  m_poptasticSettingsUi.in_verify->setChecked
    (m_settings.value("gui/poptasticVerifyPopHostPeer", 0).toInt());
  m_poptasticSettingsUi.out_verify->setChecked
    (m_settings.value("gui/poptasticVerifySmtpHostPeer", 0).toInt());

  if(!protocols.contains("pop3s"))
    {
      m_poptasticSettingsUi.in_ssltls->clear();
      m_poptasticSettingsUi.in_ssltls->addItem("None");
    }

  if(!protocols.contains("smtps"))
    {
      m_poptasticSettingsUi.out_ssltls->clear();
      m_poptasticSettingsUi.out_ssltls->addItem("None");
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

      index = m_poptasticSettingsUi.in_method->findText
	(hash["in_method"].toString());

      if(index >= 0)
	m_poptasticSettingsUi.in_method->setCurrentIndex(index);
      else
	m_poptasticSettingsUi.in_method->setCurrentIndex(2);

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
      else
	m_poptasticSettingsUi.in_ssltls->setCurrentIndex(2);

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
      else
	m_poptasticSettingsUi.out_ssltls->setCurrentIndex(2);

      m_poptasticSettingsUi.out_username->setText
	(hash["out_username"].toString());
      m_poptasticSettingsUi.proxy->setChecked
	(hash["proxy_enabled"].toBool());
      m_poptasticSettingsUi.proxy_password->setText
	(hash["proxy_password"].toString());
      m_poptasticSettingsUi.proxy_server_address->setText
	(hash["proxy_server_address"].toString());
      m_poptasticSettingsUi.proxy_server_port->setValue
	(hash["proxy_server_port"].toInt());

      index = m_poptasticSettingsUi.proxy_type->findText
	(hash["proxy_type"].toString());

      if(index >= 0)
	m_poptasticSettingsUi.proxy_type->setCurrentIndex(index);
      else
	m_poptasticSettingsUi.proxy_type->setCurrentIndex(0);

      m_poptasticSettingsUi.proxy_username->setText
	(hash["proxy_username"].toString());
    }

  if(m_poptasticDialog->exec() == QDialog::Accepted)
    {
      QSettings settings;

      m_settings["gui/disablePop3"] =
	m_poptasticSettingsUi.in_method->currentIndex() == 0 ? true : false;
      m_settings["gui/disableSmtp"] =
	m_poptasticSettingsUi.out_method->currentIndex() == 0 ? true : false;
      m_settings["gui/poptasticCAPath"] =
	m_poptasticSettingsUi.capath->text();
      m_settings["gui/poptasticName"] =
	m_poptasticSettingsUi.in_username->text().toUtf8();
      m_settings["gui/poptasticRefreshInterval"] =
	m_poptasticSettingsUi.poptasticRefresh->value();
      m_settings["gui/poptasticVerifyPopHostPeer"] =
	m_poptasticSettingsUi.in_verify->isChecked() ? 1 : 0;
      m_settings["gui/poptasticVerifySmtpHostPeer"] =
	m_poptasticSettingsUi.out_verify->isChecked() ? 1 : 0;
      settings.setValue("gui/disablePop3",
			m_poptasticSettingsUi.in_method->
			currentIndex() == 0 ? true : false);
      settings.setValue("gui/disableSmtp",
			m_poptasticSettingsUi.out_method->
			currentIndex() == 0 ? true : false);
      settings.setValue
	("gui/poptasticCAPath",
	 m_poptasticSettingsUi.capath->text());
      settings.setValue
	("gui/poptasticRefreshInterval",
	 m_poptasticSettingsUi.poptasticRefresh->value());
      settings.setValue
	("gui/poptasticVerifyPopHostPeer",
	 m_poptasticSettingsUi.in_verify->isChecked() ? 1 : 0);
      settings.setValue
	("gui/poptasticVerifySmtpHostPeer",
	 m_poptasticSettingsUi.out_verify->isChecked() ? 1 : 0);

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
	       "out_server_port, out_ssltls, out_username, "
	       "proxy_enabled, "
	       "proxy_password, proxy_server_address, proxy_server_port, "
	       "proxy_type, proxy_username) "
	       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
	       "?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, m_poptasticSettingsUi.in_authentication->currentText());
	    query.bindValue
	      (1, m_poptasticSettingsUi.in_method->currentText());
	    query.bindValue
	      (2, crypt->encryptedThenHashed(m_poptasticSettingsUi.
					     in_password->
					     text().
					     toUtf8(), &ok).toBase64());

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
					       text().
					       toUtf8(), &ok).toBase64());

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
	      query.bindValue
		(14, crypt->
		 encryptedThenHashed(QByteArray::
				     number(m_poptasticSettingsUi.proxy->
					    isChecked() ? 1 : 0),
				     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(15, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.
				     proxy_password->text().
				     toUtf8(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(16, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.
				     proxy_server_address->text().
				     trimmed().toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(17, crypt->
		 encryptedThenHashed(QByteArray::
				     number(m_poptasticSettingsUi.
					    proxy_server_port->
					    value()), &ok).toBase64());

	    query.bindValue(18, m_poptasticSettingsUi.proxy_type->
			    currentText().toLatin1());

	    if(ok)
	      query.bindValue
		(19, crypt->
		 encryptedThenHashed(m_poptasticSettingsUi.proxy_username->
				     text().trimmed().toUtf8(),
				     &ok).toBase64());

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
  m_poptasticSettingsUi.out_password->clear();
  m_poptasticSettingsUi.out_server_address->clear();
  m_poptasticSettingsUi.out_server_port->setValue(1);
  m_poptasticSettingsUi.out_username->clear();
  m_poptasticSettingsUi.proxy->setChecked(false);
  m_poptasticSettingsUi.proxy_password->clear();
  m_poptasticSettingsUi.proxy_server_address->clear();
  m_poptasticSettingsUi.proxy_server_port->setValue(1);
  m_poptasticSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticSettingsUi.proxy_username->clear();
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
	 m_poptasticSettingsUi.in_password->text().toLatin1().
	 constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 m_poptasticSettingsUi.in_username->text().trimmed().toLatin1().
	 constData());

      if(m_poptasticSettingsUi.proxy->isChecked())
	{
	  QString address("");
	  QString port("");
	  QString scheme("");
	  QString url("");

	  address = m_poptasticSettingsUi.proxy_server_address->
	    text().trimmed();
	  port = QString::number(m_poptasticSettingsUi.
				 proxy_server_port->value());

	  if(m_poptasticSettingsUi.proxy_type->currentText() == "HTTP")
	    scheme = "http";
	  else
	    scheme = "socks5";

	  url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	  curl_easy_setopt(curl, CURLOPT_PROXY, url.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			   m_poptasticSettingsUi.proxy_password->text().
			   toUtf8().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			   m_poptasticSettingsUi.proxy_username->text().
			   trimmed().toLatin1().constData());
	}

      QString method
	(m_poptasticSettingsUi.in_method->currentText().toUpper());
      QString url("");
      int index = m_poptasticSettingsUi.in_ssltls->currentIndex();

      if(index == 1 || index == 2)
	{
	  if(method == "IMAP")
	    url = QString("imaps://%1:%2/").
	      arg(m_poptasticSettingsUi.
		  in_server_address->text().trimmed()).
	      arg(m_poptasticSettingsUi.in_server_port->value());
	  else if(method == "POP3")
	    url = QString("pop3s://%1:%2/").
	      arg(m_poptasticSettingsUi.in_server_address->text().trimmed()).
	      arg(m_poptasticSettingsUi.in_server_port->value());

	  long verify = static_cast<long>
	    (m_poptasticSettingsUi.in_verify->isChecked());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(index == 2) // TLS
	    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	}
      else
	{
	  if(method == "IMAP")
	    url = QString("imap://%1:%2/").
	      arg(m_poptasticSettingsUi.in_server_address->text().trimmed()).
	      arg(m_poptasticSettingsUi.in_server_port->value());
	  else if(method == "POP3")
	    url = QString("pop3://%1:%2/").
	      arg(m_poptasticSettingsUi.in_server_address->text().trimmed()).
	      arg(m_poptasticSettingsUi.in_server_port->value());
	}

      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
      curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());
      res = curl_easy_perform(curl);

      if(res == CURLE_OK)
	ok = true;

      curl_easy_cleanup(curl);
    }

  QApplication::restoreOverrideCursor();

  if(ok)
    QMessageBox::information
      (this, tr("%1: Poptastic Incoming Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Test successful!"));
  else
    QMessageBox::critical
      (this, tr("%1: Poptastic Incoming Connection Test").
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
	 m_poptasticSettingsUi.out_password->text().toLatin1().
	 constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 m_poptasticSettingsUi.out_username->text().trimmed().toLatin1().
	 constData());

      if(m_poptasticSettingsUi.proxy->isChecked())
	{
	  QString address("");
	  QString port("");
	  QString scheme("");
	  QString url("");

	  address = m_poptasticSettingsUi.proxy_server_address->
	    text().trimmed();
	  port = QString::number(m_poptasticSettingsUi.
				 proxy_server_port->value());

	  if(m_poptasticSettingsUi.proxy_type->currentText() == "HTTP")
	    scheme = "http";
	  else
	    scheme = "socks5";

	  url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	  curl_easy_setopt(curl, CURLOPT_PROXY, url.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			   m_poptasticSettingsUi.proxy_password->text().
			   toUtf8().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			   m_poptasticSettingsUi.proxy_username->text().
			   trimmed().toLatin1().constData());
	}

      QString method
	(m_poptasticSettingsUi.out_method->currentText().toUpper());
      QString url("");
      int index = m_poptasticSettingsUi.out_ssltls->currentIndex();

      if(index == 1 || index == 2)
	{
	  if(method == "SMTP")
	    {
	      if(index == 1) // SSL
		url = QString("smtps://%1:%2/").
		  arg(m_poptasticSettingsUi.out_server_address->text().
		      trimmed()).
		  arg(m_poptasticSettingsUi.out_server_port->value());
	      else // TLS
		url = QString("smtp://%1:%2/").
		  arg(m_poptasticSettingsUi.out_server_address->text().
		      trimmed()).
		  arg(m_poptasticSettingsUi.out_server_port->value());
	    }

	  long verify = static_cast<long>
	    (m_poptasticSettingsUi.out_verify->isChecked());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(index == 2) // TLS
	    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	}
      else
	{
	  if(method == "SMTP")
	    url = QString("smtp://%1:%2/").
	      arg(m_poptasticSettingsUi.out_server_address->text().trimmed()).
	      arg(m_poptasticSettingsUi.out_server_port->value());
	}

      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
      curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());
      res = curl_easy_perform(curl);

      if(res == CURLE_OK)
	ok = true;

      curl_easy_cleanup(curl);
    }

  QApplication::restoreOverrideCursor();

  if(ok)
    QMessageBox::information
      (this, tr("%1: Poptastic Outgoing Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Test successful!"));
  else
    QMessageBox::critical
      (this, tr("%1: Poptastic Outgoing Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Failure!"));
}

void spoton::slotPoptasticSettingsReset(bool state)
{
  Q_UNUSED(state);
  m_poptasticSettingsUi.proxy_password->clear();
  m_poptasticSettingsUi.proxy_server_address->clear();
  m_poptasticSettingsUi.proxy_server_port->setValue(1);
  m_poptasticSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticSettingsUi.proxy_username->clear();
}

void spoton::slotPoptasticSettingsReset(void)
{
  m_poptasticSettingsUi.capath->clear();
  m_poptasticSettingsUi.in_method->setCurrentIndex(2);
  m_poptasticSettingsUi.in_password->clear();
  m_poptasticSettingsUi.in_server_address->clear();
  m_poptasticSettingsUi.in_server_port->setValue(995);
  m_poptasticSettingsUi.in_ssltls->setCurrentIndex(2);
  m_poptasticSettingsUi.in_username->clear();
  m_poptasticSettingsUi.in_verify->setChecked(false);
  m_poptasticSettingsUi.out_method->setCurrentIndex(1);
  m_poptasticSettingsUi.out_password->clear();
  m_poptasticSettingsUi.out_server_address->clear();
  m_poptasticSettingsUi.out_server_port->setValue(587);
  m_poptasticSettingsUi.out_ssltls->setCurrentIndex(2);
  m_poptasticSettingsUi.out_username->clear();
  m_poptasticSettingsUi.out_verify->setChecked(false);
  m_poptasticSettingsUi.poptasticRefresh->setValue(5.00);
  m_poptasticSettingsUi.proxy->setChecked(false);
  m_poptasticSettingsUi.proxy_password->clear();
  m_poptasticSettingsUi.proxy_server_address->clear();
  m_poptasticSettingsUi.proxy_server_port->setValue(1);
  m_poptasticSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticSettingsUi.proxy_username->clear();
}

void spoton::slotSelectCAPath(void)
{
  QString fileName("");

  if(m_poptasticSettingsUi.selectcapath == sender())
    {
      QFileDialog dialog(this);

      dialog.setWindowTitle
	(tr("%1: Select CA File").
	 arg(SPOTON_APPLICATION_NAME));
      dialog.setFileMode(QFileDialog::ExistingFile);
      dialog.setDirectory(QDir::homePath());
      dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
      dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

      if(dialog.exec() == QDialog::Accepted)
	{
	  fileName = dialog.selectedFiles().value(0);
	  m_poptasticSettingsUi.capath->setText
	    (dialog.selectedFiles().value(0));
	}
    }
  else
    fileName = m_poptasticSettingsUi.capath->text();
}

void spoton::slotSetNeighborPriority(void)
{
  QAction *action = qobject_cast<QAction *> (sender());
  QThread::Priority priority = QThread::HighPriority;

  if(!action)
    return;
  else
    priority = QThread::Priority(action->property("priority").toInt());

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  if(priority < 0 || priority > 7)
    priority = QThread::HighPriority;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "priority = ? "
		      "WHERE OID = ?");
	query.bindValue(0, priority);
	query.bindValue(1, list.at(0).data());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
