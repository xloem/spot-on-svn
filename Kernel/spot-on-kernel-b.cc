/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
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

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"

static QByteArray curl_payload_text[11];

struct curl_upload_status
{
  int lines_read;
};

static size_t curl_payload_source
(void *ptr, size_t size, size_t nmemb, void *userp)
{
  if(nmemb == 0 || !ptr || size == 0 || (nmemb * size) < 1 || !userp)
    return 0;

  struct curl_upload_status *upload_ctx =
    (struct curl_upload_status *) userp;

  if(!upload_ctx || upload_ctx->lines_read > 11)
    return 0;

  const char *data = curl_payload_text[upload_ctx->lines_read].constData();

  if(data)
    {
      size_t length = strlen(data);

      memcpy(ptr, data, length);
      upload_ctx->lines_read++;
      return length;
    }

  return 0;
}

void spoton_kernel::slotPoptasticPop(void)
{
}

void spoton_kernel::slotPoptasticPost(void)
{
  if(m_poptasticPostFuture.isFinished())
    m_statisticsFuture =
      QtConcurrent::run(this, &spoton_kernel::postPoptastic);
}

void spoton_kernel::popPoptastic(void)
{
}

void spoton_kernel::postPoptastic(void)
{
  QReadLocker locker(&m_poptasticCacheMutex);

  if(!m_poptasticCache.isEmpty())
    {
      locker.unlock();

      spoton_crypt *s_crypt = s_crypts.value("chat", 0);

      if(!s_crypt)
	return;

      QHash<QString, QVariant> hash;
      bool ok = true;

      hash = spoton_misc::poptasticSettings(s_crypt, &ok);

      if(!ok)
	return;

      CURL *curl = 0;
      curl = curl_easy_init();

      if(curl)
	{
	  QPair<QString, QByteArray> pair;
	  QWriteLocker locker(&m_poptasticCacheMutex);

	  pair = m_poptasticCache.dequeue();
	  locker.unlock();

	  struct curl_slist *recipients = 0;
	  struct curl_upload_status upload_ctx;

	  upload_ctx.lines_read = 0;
	  curl_easy_setopt
	    (curl, CURLOPT_USERNAME,
	     hash["out_username"].toByteArray().trimmed().constData());
	  curl_easy_setopt
	    (curl, CURLOPT_PASSWORD,
	     hash["out_password"].toByteArray().trimmed().constData());

	  QString from(setting("gui/poptasticName", "unknown@unknown.org").
		       toString());
	  QString ssltls(hash["out_ssltls"].toString().toUpper().trimmed());
	  QString url("");

	  if(ssltls == tr("SSL") || ssltls == tr("TLS"))
	    {
	      if(ssltls == tr("SSL"))
		url = QString("smtps://%1:%2/").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed());
	      else
		url = QString("smtp://%1:%2/").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed());

	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	      if(ssltls == tr("TLS"))
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	    }
	  else
	    url = QString("smtp://%1:%2/").
	      arg(hash["out_server_address"].toString().trimmed()).
	      arg(hash["out_server_port"].toString().trimmed());

	  curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());
	  curl_easy_setopt
	    (curl, CURLOPT_MAIL_FROM,
	     QString("<%1>").arg(from).toLatin1().constData());

	  /*
	  ** Prepare curl_payload_text.
	  */

	  curl_payload_text[0] = QString("Date: %1\r\n").arg
	    (QDateTime::currentDateTime().toUTC().toString()).toLatin1();
	  curl_payload_text[1] = QString("To: <%1> (%1)\r\n").arg(pair.first).
	    toLatin1();
	  curl_payload_text[2] = QString("From: <%1>\r\n").arg(from).
	    toLatin1();
	  curl_payload_text[3] =
	    QString("Message-ID: <%1>\r\n").
	    arg(spoton_crypt::weakRandomBytes(16).toHex().
		constData()).toLatin1();
	  curl_payload_text[4] =
	    QString("Subject: %1\r\n").
	    arg(spoton_crypt::weakRandomBytes(16).toHex().
		constData()).toLatin1();
	  curl_payload_text[5] = "\r\n";
	  curl_payload_text[6] =
	    QString("%1\r\n").arg(pair.second.constData()).toLatin1().
	    constData();
	  curl_payload_text[7] = "\r\n";
	  curl_payload_text[8] = "\r\n";
	  curl_payload_text[9] = "\r\n";
	  curl_payload_text[10] = 0;
	  recipients = curl_slist_append
	    (recipients, pair.first.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	  curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_payload_source);
	  curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
	  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	  curl_easy_perform(curl);
	  curl_slist_free_all(recipients);
	  curl_easy_cleanup(curl);
	}
    }
}
