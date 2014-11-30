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
#include "Common/spot-on-receive.h"
#include "spot-on-kernel.h"

#include <QSqlQuery>

static QByteArray curl_payload_text[11];

struct curl_memory
{
  char *memory;
  size_t size;
};

struct curl_upload_status
{
  int lines_read;
};

static size_t curl_payload_source
(void *ptr, size_t size, size_t nmemb, void *userp)
{
  if(nmemb <= 0 || !ptr || size <= 0 || (nmemb * size) < 1 || !userp)
    return 0;

  struct curl_upload_status *upload_ctx =
    (struct curl_upload_status *) userp;

  if(!upload_ctx || upload_ctx->lines_read >= 11)
    return 0;

  const char *data = curl_payload_text[upload_ctx->lines_read].constData();

  if(data)
    {
      size_t length = strlen(data);

      if(length > 0)
	memcpy(ptr, data, length);

      upload_ctx->lines_read++;
      return length;
    }

  return 0;
}

static size_t curl_write_memory_callback(void *contents, size_t size,
					 size_t nmemb, void *userp)
{
  if(!contents || nmemb <= 0 || size <= 0 || !userp)
    return 0;

  struct curl_memory *memory = (struct curl_memory *) userp;

  if(!memory)
    return 0;

  size_t realsize = nmemb * size;

  memory->memory = (char *)
    realloc(memory->memory, memory->size + realsize + 1);

  if(!memory->memory)
    return 0;

  memcpy(&(memory->memory[memory->size]), contents, realsize);
  memory->size += realsize;
  memory->memory[memory->size] = 0;
  return realsize;
}

void spoton_kernel::slotPoptasticPopPost(void)
{
  if(m_poptasticPopPostFuture.isFinished())
    m_poptasticPopPostFuture =
      QtConcurrent::run(this, &spoton_kernel::popPostPoptastic);
}

void spoton_kernel::popPostPoptastic(void)
{
  spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

  if(!s_crypt)
    return;

  QHash<QString, QVariant> hash;
  bool ok = true;

  hash = spoton_misc::poptasticSettings(s_crypt, &ok);

  if(hash.isEmpty() || !ok)
    return;

  /*
  ** First, we pop!
  */

  if(!setting("gui/disablePop3", false).toBool())
    {
      CURL *curl = curl_easy_init();

      if(curl)
	{
	  curl_easy_setopt
	    (curl, CURLOPT_PASSWORD,
	     hash["in_password"].toByteArray().constData());
	  curl_easy_setopt
	    (curl, CURLOPT_USERNAME,
	     hash["in_username"].toByteArray().constData());

	  QString ssltls(hash["in_ssltls"].toString().toUpper().trimmed());
	  QString url("");

	  if(ssltls == "SSL" || ssltls == "TLS")
	    {
	      url = QString("pop3s://%1:%2/1").
		arg(hash["in_server_address"].toString().trimmed()).
		arg(hash["in_server_port"].toString().trimmed());
	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	      if(ssltls == "TLS")
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	      }
	  else
	    url = QString("pop3://%1:%2/1").
	      arg(hash["in_server_address"].toString().trimmed()).
	      arg(hash["in_server_port"].toString().trimmed());

	  curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());

	  for(int i = 1; i <= 5; i++)
	    {
	      struct curl_memory chunk;

	      chunk.memory = (char *) malloc(1);

	      if(!chunk.memory)
		break;

	      chunk.size = 0;
	      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
	      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
	      curl_easy_setopt
		(curl, CURLOPT_WRITEFUNCTION, curl_write_memory_callback);

	      if(curl_easy_perform(curl) == CURLE_OK)
		if(chunk.size > 0)
		  emit poppedMessage(QByteArray(chunk.memory, chunk.size));

	      free(chunk.memory);

	      if(m_poptasticPopPostFuture.isCanceled())
		break;
	    }

	  curl_easy_cleanup(curl);
	}
    }

  if(m_poptasticPopPostFuture.isCanceled())
    return;

  /*
  ** Now, we post!
  */

  QReadLocker locker(&m_poptasticCacheMutex);

  if(!m_poptasticCache.isEmpty())
    {
      locker.unlock();

      CURL *curl = curl_easy_init();

      if(curl)
	{
	  curl_easy_setopt
	    (curl, CURLOPT_PASSWORD,
	     hash["out_password"].toByteArray().trimmed().constData());
	  curl_easy_setopt
	    (curl, CURLOPT_USERNAME,
	     hash["out_username"].toByteArray().trimmed().constData());

	  QString from
	    (setting("gui/poptasticName", "unknown@unknown.org").toString());
	  QString ssltls(hash["out_ssltls"].toString().toUpper().trimmed());
	  QString url("");

	  if(ssltls == "SSL" || ssltls == "TLS")
	    {
	      if(ssltls == "SSL")
		url = QString("smtps://%1:%2/").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed());
	      else
		url = QString("smtp://%1:%2/").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed());

	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	      if(ssltls == "TLS")
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	    }
	  else
	    url = QString("smtp://%1:%2/").
	      arg(hash["out_server_address"].toString().trimmed()).
	      arg(hash["out_server_port"].toString().trimmed());

	  curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());

	  for(int i = 1; i <= 5; i++)
	    {
	      QPair<QString, QByteArray> pair;
	      QWriteLocker locker(&m_poptasticCacheMutex);

	      if(m_poptasticCache.isEmpty())
		break;
	      else
		pair = m_poptasticCache.dequeue();

	      locker.unlock();

	      struct curl_slist *recipients = 0;
	      struct curl_upload_status upload_ctx;

	      upload_ctx.lines_read = 0;
	      curl_easy_setopt
		(curl, CURLOPT_MAIL_FROM,
		 QString("<%1>").arg(from).toLatin1().constData());
	      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	      /*
	      ** Prepare curl_payload_text.
	      */

	      curl_payload_text[0] = QString("Date: %1\r\n").arg
		(QDateTime::currentDateTime().toUTC().toString()).toLatin1();
	      curl_payload_text[1] = QString("To: <%1> (%1)\r\n").
		arg(pair.first).
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
	      curl_easy_setopt
		(curl, CURLOPT_READFUNCTION, curl_payload_source);
	      curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
	      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	      curl_easy_perform(curl);
	      curl_slist_free_all(recipients);

	      if(m_poptasticPopPostFuture.isCanceled())
		break;
	    }

	  curl_easy_cleanup(curl);
	}
    }
}

void spoton_kernel::slotPoppedMessage(const QByteArray &message)
{
  QByteArray data
    (message.
     mid(message.indexOf("content=") + qstrlen("content="),
	 message.indexOf(spoton_send::EOM) + spoton_send::EOM.length()).
     trimmed());

  if(data.isEmpty())
    return;
  else if(data.length() > spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE)
    {
      spoton_misc::logError
	(QString("spoton_kernel::slotPoppedMessage(): "
		 "too much data (%1 bytes). "
		 "Ignoring.").
	 arg(data.length()));
      return;
    }

  /*
  ** The following logic must agree with the logic in
  ** spot-on-neighbor.cc.
  */

  QList<QByteArray> symmetricKeys;
  QString messageType
    (spoton_receive::findMessageType(data, symmetricKeys,
				     interfaces(),
				     s_crypts,
				     "poptastic"));

  if(messageType == "0000")
    {
      QByteArray messageCode;
      QList<QByteArray> list
	(spoton_receive::
	 process0000(data.length(), data, symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).
		     toBool(),
		     QHostAddress("127.0.0.1"), 0,
		     messageCode,
		     s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	{
	  spoton_misc::saveParticipantStatus
	    (list.value(1), // Name
	     list.value(0), // Public Key Hash
	     QByteArray(),  // Status
	     QDateTime::currentDateTime().toString("MMddyyyyhhmmss").
	     toLatin1(),    // Timestamp
	     60,            // Seconds
	     s_crypts.value("chat", 0));
	  emit receivedChatMessage
	    ("message_" +
	     list.value(0).toBase64() + "_" +
	     list.value(1).toBase64() + "_" +
	     list.value(2).toBase64() + "_" +
	     list.value(3).toBase64() + "_" +
	     list.value(4).toBase64() + "_" +
	     messageCode.toBase64().append('\n'));
	}
    }
  else if(messageType == "0000a")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0000a(data.length(), data,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      QHostAddress("127.0.0.1"), 0,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(0), list.value(1),
		   list.value(2), list.value(3),
		   "0000a");
    }
  else if(messageType == "0000b")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0000b(data.length(), data, symmetricKeys,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      QHostAddress("127.0.0.1"), 0,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(1), list.value(2),
		   list.value(3), list.value(4),
		   "0000b");
    }
  else if(messageType == "0013")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0013(data.length(), data, symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).
		     toBool(),
		     QHostAddress("127.0.0.1"), 0,
		     s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	spoton_misc::saveParticipantStatus
	  (list.value(1),  // Name
	   list.value(0),  // Public Key Hash
	   list.value(2),  // Status
	   list.value(3),  // Timestamp
	   60,             // Seconds
	   s_crypts.value("chat"));
    }
}

void spoton_kernel::saveGemini(const QByteArray &publicKeyHash,
			       const QByteArray &gemini,
			       const QByteArray &geminiHashKey,
			       const QByteArray &timestamp,
			       const QString &messageType)
{
  /*
  ** Some of the following is similar to logic in
  ** spot-on-neighbor.cc.
  */

  QDateTime dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      spoton_misc::logError
	("spoton_kernel(): saveGemini(): invalid date-time object.");
      return;
    }

  QDateTime now(QDateTime::currentDateTimeUtc());

  dateTime.setTimeSpec(Qt::UTC);
  now.setTimeSpec(Qt::UTC);

  int secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= 90))
    {
      spoton_misc::logError
	(QString("spoton_kernel::saveGemini(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }
  else if(duplicateGeminis(publicKeyHash +
			   gemini +
			   geminiHashKey))
    {
      spoton_misc::logError
	("spoton_kernel::saveGemini(): duplicate keys.");
      return;
    }

  geminisCacheAdd(publicKeyHash + gemini + geminiHashKey);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QPair<QByteArray, QByteArray> geminis;
	QSqlQuery query(db);
	bool ok = true;

	geminis.first = gemini;
	geminis.second = geminiHashKey;
	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ?, "
		      "last_status_update = ? "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");

	if(geminis.first.isEmpty() || geminis.second.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    spoton_crypt *s_crypt = s_crypts.value("chat", 0);

	    if(s_crypt)
	      {
		query.bindValue
		  (0, s_crypt->encryptedThenHashed(geminis.first, &ok).
		   toBase64());

		if(ok)
		  query.bindValue
		    (1, s_crypt->encryptedThenHashed(geminis.second,
						     &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
	      }
	  }

	query.bindValue
	  (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(3, publicKeyHash.toBase64());

	if(ok)
	  if(query.exec())
	    {
	      if(geminis.first.isEmpty() ||
		 geminis.second.isEmpty())
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 terminated the call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	      else if(messageType == "0000a")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	      else if(messageType == "0000b")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call "
		      "within a call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
