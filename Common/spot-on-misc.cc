/*
** Copyright (c) 2011 - 2014 Alexis Megas
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

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QLocale>
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QString>

#include <limits>

#include "spot-on-common.h"
#include "spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-send.h"

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
extern "C"
{
#include <GeoIP.h>
}
#endif

QMutex spoton_misc::s_dbMutex;
bool spoton_misc::s_enableLog = false; // Not protected by a mutex.
quint64 spoton_misc::s_dbId = 0;

QString spoton_misc::homePath(void)
{
  QString homepath(qgetenv("SPOTON_HOME").trimmed());

  if(homepath.isEmpty())
#ifdef Q_OS_WIN32
    return QDir::currentPath() + QDir::separator() + ".spot-on";
#else
    return QDir::homePath() + QDir::separator() + ".spot-on";
#endif
  else
    return homepath;
}

bool spoton_misc::isGnome(void)
{
  QString session(qgetenv("DESKTOP_SESSION").toLower().trimmed());

  if(session == "gnome" || session == "ubuntu")
    return true;
  else
    return false;
}

void spoton_misc::prepareDatabases(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "buzz_channels.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS buzz_channels ("
		   "data BLOB NOT NULL, "
		   "data_hash TEXT PRIMARY KEY NOT NULL)"); // Keyed hash.
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS folders ("
		   "date TEXT NOT NULL, "
		   "folder_index INTEGER NOT NULL, "
		   "goldbug TEXT NOT NULL, " /*
					     ** "0" or "1" for inbound.
					     ** Symmetric key for outbound.
					     */
		   "hash TEXT NOT NULL, " /*
					  ** Keyed hash of the message and
					  ** the subject.
					  */
		   "message BLOB NOT NULL, "
		   "message_code TEXT NOT NULL, " /*
						  ** Not yet used.
						  */
		   "participant_oid TEXT NOT NULL, " // Encrypted?
		   "receiver_sender TEXT NOT NULL, "
		   "receiver_sender_hash TEXT NOT NULL, " /*
							  ** SHA-512 hash of
							  ** the receiver's
							  ** or the sender's
							  ** public key.
							  */
		   "status TEXT NOT NULL, " /*
					    ** Deleted, read, etc.
					    */
		   "subject BLOB NOT NULL, "
		   "PRIMARY KEY (folder_index, hash, receiver_sender_hash))");
	query.exec("CREATE TABLE IF NOT EXISTS post_office ("
		   "date_received TEXT NOT NULL, "
		   "message_bundle BLOB NOT NULL, "
		   "message_bundle_hash TEXT NOT NULL, " // Keyed hash.
		   "recipient_hash TEXT NOT NULL, " /*
						    ** SHA-512 hash of the
						    ** recipient's public
						    ** key.
						    */
		   "PRIMARY KEY (recipient_hash, message_bundle_hash))");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec
	  ("CREATE TABLE IF NOT EXISTS friends_public_keys ("
	   "gemini TEXT DEFAULT NULL, "
	   "key_type TEXT NOT NULL DEFAULT 'chat', "
	   "name TEXT NOT NULL DEFAULT 'unknown', "
	   "public_key TEXT NOT NULL, "
	   "public_key_hash TEXT PRIMARY KEY NOT NULL, " /*
							 ** SHA-512
							 ** hash of
							 ** the public
							 ** key.
							 */
	   /*
	   ** Why do we need the neighbor's OID?
	   ** When a neighbor shares a public key, we need
	   ** to be able to remove the key if the socket connection
	   ** is lost before we complete the exchange. The field
	   ** provides us with some safety.
	   */
	   "neighbor_oid INTEGER NOT NULL DEFAULT -1, "
	   "status TEXT NOT NULL DEFAULT 'offline', "
	   "last_status_update TEXT NOT NULL DEFAULT 'now', "
	   "gemini_hash_key TEXT DEFAULT NULL)");
	query.exec
	  ("CREATE TABLE IF NOT EXISTS relationships_with_signatures ("
	   "public_key_hash TEXT PRIMARY KEY NOT NULL, " /*
							 ** SHA-512
							 ** hash of
							 ** the public
							 ** key.
							 */
	   "signature_public_key_hash "
	   "TEXT NOT NULL)"); /*
			      ** SHA-512 hash of the signature
			      ** public key.
			      */
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS idiotes ("
		   "id TEXT PRIMARY KEY NOT NULL, "
		   "public_key BLOB NOT NULL, "
		   "private_key BLOB NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS kernel_gui_server ("
		   "port INTEGER PRIMARY KEY NOT NULL)");
	query.exec("CREATE TRIGGER IF NOT EXISTS kernel_gui_server_trigger "
		   "BEFORE INSERT ON kernel_gui_server "
		   "BEGIN "
		   "DELETE FROM kernel_gui_server; "
		   "END");
	query.exec("CREATE TABLE IF NOT EXISTS kernel_statistics ("
		   "statistic TEXT PRIMARY KEY NOT NULL, "
		   "value TEXT)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec
	  (QString("CREATE TABLE IF NOT EXISTS listeners ("
		   "ip_address TEXT NOT NULL, "
		   "port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'offline', "
		   "status_control TEXT NOT NULL DEFAULT 'online', "
		   "connections INTEGER NOT NULL DEFAULT 0, "
		   "maximum_clients INTEGER NOT NULL DEFAULT 5, "
		   "external_ip_address TEXT, "
		   "external_port TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** The keyed hash of
						      ** the IP address,
						      ** the port,
						      ** the scope id, and
						      ** the transport.
						      */
		   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
		   "echo_mode TEXT NOT NULL, "
		   "certificate BLOB NOT NULL, "
		   "private_key BLOB NOT NULL, "
		   "public_key BLOB NOT NULL, "       // Not used.
		   "use_accounts INTEGER NOT NULL DEFAULT 0, "
		   "maximum_buffer_size INTEGER NOT NULL DEFAULT %1, "
		   "maximum_content_length INTEGER NOT NULL DEFAULT %2, "
		   "transport TEXT NOT NULL, "
		   "share_udp_address INTEGER NOT NULL DEFAULT 0, "
		   "orientation TEXT NOT NULL, "
		   "motd TEXT NOT NULL DEFAULT 'Welcome to Spot-On.')").
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH));
	query.exec("CREATE TABLE IF NOT EXISTS listeners_accounts ("
		   "account_name TEXT NOT NULL, "
		   "account_name_hash TEXT NOT NULL, " // Keyed hash.
		   "account_password TEXT NOT NULL, "
		   "listener_oid INTEGER NOT NULL, "
		   "one_time_account INTEGER NOT NULL DEFAULT 0, "
		   "PRIMARY KEY (listener_oid, account_name_hash), "
		   "FOREIGN KEY (listener_oid) REFERENCES "
		   "listeners (OID))"); /*
					** The foreign key constraint
					** is flawed.
					*/
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "listeners_accounts_consumed_authentications ("
		   "data TEXT NOT NULL, "
		   "insert_date TEXT NOT NULL DEFAULT 'now', "
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (listener_oid, data), "
		   "FOREIGN KEY (listener_oid) REFERENCES "
		   "listeners (OID))"); /*
					** The foreign key constraint
					** is flawed.
					*/
	query.exec("CREATE TABLE IF NOT EXISTS listeners_allowed_ips ("
		   "ip_address TEXT NOT NULL, "
		   "ip_address_hash TEXT NOT NULL, " // Keyed hash.
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (ip_address_hash, listener_oid), "
		   "FOREIGN KEY (listener_oid) REFERENCES "
		   "listeners (OID))"); /*
					** The foreign key constraint
					** is flawed.
					*/
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec
	  (QString("CREATE TABLE IF NOT EXISTS neighbors ("
		   "local_ip_address TEXT , "
		   "local_port TEXT, "
		   "remote_ip_address TEXT NOT NULL, "
		   "remote_port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'disconnected', "
		   "status_control TEXT NOT NULL DEFAULT 'connected', "
		   "sticky INTEGER NOT NULL DEFAULT 1, "
		   "external_ip_address TEXT, "
		   "external_port TEXT, "
		   "uuid TEXT NOT NULL, "
		   "country TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** Keyed hash of the
						      ** proxy IP address,
						      ** the proxy port,
						      ** the remote IP
						      ** address, the remote
						      ** port, the scope id,
						      ** and the transport.
						      */
		   "remote_ip_address_hash TEXT NOT NULL, " // Keyed hash.
		   "qt_country_hash TEXT, " // Keyed hash.
		   "user_defined INTEGER NOT NULL DEFAULT 1, "
		   "proxy_hostname TEXT NOT NULL, "
		   "proxy_password TEXT NOT NULL, "
		   "proxy_port TEXT NOT NULL, "
		   "proxy_type TEXT NOT NULL, "
		   "proxy_username TEXT NOT NULL, "
		   "is_encrypted INTEGER NOT NULL DEFAULT 0, "
		   "maximum_buffer_size INTEGER NOT NULL DEFAULT %1, "
		   "maximum_content_length INTEGER NOT NULL DEFAULT %2, "
		   "echo_mode TEXT NOT NULL, "
		   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
		   "uptime INTEGER NOT NULL DEFAULT 0, "
		   "certificate BLOB NOT NULL, "
		   "allow_exceptions INTEGER NOT NULL DEFAULT 0, "
		   "bytes_read INTEGER NOT NULL DEFAULT 0, "
		   "bytes_written INTEGER NOT NULL DEFAULT 0, "
		   "ssl_session_cipher TEXT, "
		   "ssl_required INTEGER NOT NULL DEFAULT 1, "
		   "account_name TEXT NOT NULL, "
		   "account_password TEXT NOT NULL, "
		   "account_authenticated TEXT, "
		   "transport TEXT NOT NULL, "
		   "orientation TEXT NOT NULL, "
		   "motd TEXT NOT NULL DEFAULT 'Welcome to Spot-On.')").
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS magnets ("
		   "magnet BLOB NOT NULL, "
		   "magnet_hash TEXT PRIMARY KEY NOT NULL, " // Keyed hash.
		   "one_time_magnet INTEGER NOT NULL DEFAULT 1)");
	query.exec("CREATE TABLE IF NOT EXISTS received ("
		   "file TEXT NOT NULL, "
		   "file_hash TEXT PRIMARY KEY NOT NULL, " /*
							   ** Keyed hash of
							   ** the file name.
							   */
		   "hash TEXT, "                           /*
							   ** Hash of
							   ** the file.
							   */
		   "pulse_size TEXT NOT NULL, "
		   "total_size TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS received_novas ("
		   "nova TEXT NOT NULL, "
		   "nova_hash TEXT PRIMARY KEY NOT NULL)"); // Keyed hash.
	query.exec("CREATE TABLE IF NOT EXISTS transmitted ("
		   "file TEXT NOT NULL, "
		   "hash TEXT NOT NULL, " /*
					  ** Keyed hash of the file.
					  */
		   "mosaic TEXT PRIMARY KEY NOT NULL, "
		   "nova TEXT NOT NULL, "
		   "position TEXT NOT NULL, "
		   "pulse_size TEXT NOT NULL, "
		   "status_control TEXT NOT NULL DEFAULT 'paused', "
		   "total_size TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS transmitted_magnets ("
		   "magnet BLOB NOT NULL, "
		   "magnet_hash TEXT NOT NULL, " // Keyed hash.
		   "transmitted_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (magnet_hash, transmitted_oid), "
		   "FOREIGN KEY (transmitted_oid) REFERENCES "
		   "transmitted (OID))"); /*
					  ** The foreign key constraint
					  ** is flawed.
					  */
	query.exec("CREATE TABLE IF NOT EXISTS transmitted_scheduled_pulses ("
		   "position TEXT NOT NULL, "
		   "position_hash TEXT NOT NULL, " // Keyed hash.
		   "transmitted_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (position_hash, transmitted_oid), "
		   "FOREIGN KEY (transmitted_oid) REFERENCES "
		   "transmitted (OID))"); /*
					  ** The foreign key constraint
					  ** is flawed.
					  */
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  /*
  ** We shall prepare the URL databases somewhere else.
  */
}

void spoton_misc::logError(const QString &error)
{
  if(!s_enableLog)
    return;

  if(error.trimmed().isEmpty())
    return;

  QFile file(homePath() + QDir::separator() + "error_log.dat");

  if(file.size() >= 25 * 1024 * 1024)
    /*
    ** Too large!
    */

    file.remove();

  if(file.open(QIODevice::Append | QIODevice::WriteOnly))
    {
      QDateTime now(QDateTime::currentDateTime());
#ifdef Q_OS_WIN32
      QString eol("\r\n");
#else
      QString eol('\n');
#endif

      file.write(now.toString().toLatin1());
      file.write(eol.toLatin1());
      file.write(error.trimmed().toLatin1());
      file.write(eol.toLatin1());
      file.write(eol.toLatin1());
      file.flush();
    }

  file.close();
}

QString spoton_misc::countryCodeFromIPAddress(const QString &ipAddress)
{
  const char *code = 0;

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  GeoIP *gi = 0;
  QFileInfo fileInfo;
  QSettings settings;
  QString fileName(settings.value("gui/geoipPath", "GeoIP.dat").toString());

  fileInfo.setFile(fileName);

  if(fileInfo.isReadable())
    gi = GeoIP_open(fileName.toUtf8().constData(), GEOIP_MEMORY_CACHE);

  if(gi)
    code = GeoIP_country_code_by_addr
      (gi, ipAddress.toLatin1().constData());
  else
    logError("spoton_misc::countryCodeFromIPAddress(): gi is 0.");

  GeoIP_delete(gi);
#else
  Q_UNUSED(ipAddress);
#endif

  if(!code || qstrnlen(code, 2) == 0)
    return QString("Unknown");
  else
    return QString(code);
}

QString spoton_misc::countryNameFromIPAddress(const QString &ipAddress)
{
  const char *country = 0;

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  GeoIP *gi = 0;
  QFileInfo fileInfo;
  QSettings settings;
  QString fileName(settings.value("gui/geoipPath", "GeoIP.dat").toString());

  fileInfo.setFile(fileName);

  if(fileInfo.isReadable())
    gi = GeoIP_open(fileName.toUtf8().constData(), GEOIP_MEMORY_CACHE);

  if(gi)
    country = GeoIP_country_name_by_addr
      (gi, ipAddress.toLatin1().constData());
  else
    logError("spoton_misc::countryNameFromIPAddress(): gi is 0.");

  GeoIP_delete(gi);
#else
  Q_UNUSED(ipAddress);
#endif

  if(!country || qstrnlen(country, 256) == 0)
    return QString("Unknown");
  else
    return QString(country);
}

void spoton_misc::populateUrlsDatabase(const QList<QList<QVariant> > &list,
				       spoton_crypt *crypt)
{
  if(!crypt)
    return;
  else if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    /*
    ** Determine the correct URL database file.
    */

    if(db.open())
      {
	QSqlQuery query1(db);
	QSqlQuery query2(db);

	query1.prepare("INSERT INTO urls (date_time_inserted, "
		       "description, hash, title, url) "
		       "VALUES (?, ?, ?, ?, ?)");

	for(int i = 0; i < list.size(); i++)
	  {
	    /*
	    ** 0: description
	    ** 1: title
	    ** 2: url
	    */

	    QList<QVariant> variants(list.at(i));
	    bool ok = true;

	    query1.bindValue
	      (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query1.bindValue
	      (1, crypt->encrypted(variants.value(0).toByteArray(), &ok).
	       toBase64());

	    if(ok)
	      query1.bindValue
		(2, crypt->keyedHash(variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.bindValue
		(3, crypt->encrypted(variants.value(1).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.bindValue
		(4, crypt->encrypted(variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

bool spoton_misc::saveFriendshipBundle(const QByteArray &keyType,
				       const QByteArray &name,
				       const QByteArray &publicKey,
				       const QByteArray &sPublicKey,
				       const qint64 neighborOid,
				       const QSqlDatabase &db)
{
  if(!db.isOpen())
    return false;

  QSqlQuery query(db);
  bool ok = true;

  query.prepare("INSERT OR REPLACE INTO friends_public_keys "
		"(gemini, gemini_hash_key, key_type, name, public_key, "
		"public_key_hash, "
		"neighbor_oid, last_status_update) "
		"VALUES ((SELECT gemini FROM friends_public_keys WHERE "
		"public_key_hash = ?), "
		"(SELECT gemini_hash_key FROM friends_public_keys WHERE "
		"public_key_hash = ?), "
		"?, ?, ?, ?, ?, ?)");
  query.bindValue(0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue(1, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  query.bindValue(2, keyType.constData());

  if(keyType == "chat" || keyType == "email" ||
     keyType == "rosetta" || keyType == "url")
    {
      if(name.isEmpty())
	query.bindValue(3, "unknown");
      else
	query.bindValue
	  (3, name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
    }
  else // Signature keys will be labeled as their type.
    query.bindValue(3, keyType.constData());

  query.bindValue(4, publicKey);

  if(ok)
    query.bindValue
      (5, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  query.bindValue(6, neighborOid);
  query.bindValue
    (7, QDateTime::currentDateTime().toString(Qt::ISODate));

  if(ok)
    ok = query.exec();

  if(ok)
    if(!sPublicKey.isEmpty())
      {
	/*
	** Record the relationship between the public key and the
	** signature public key.
	*/

	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO relationships_with_signatures "
		      "(public_key_hash, signature_public_key_hash) "
		      "VALUES (?, ?)");
	query.bindValue
	  (0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, spoton_crypt::sha512Hash(sPublicKey, &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

  return ok;
}

void spoton_misc::retrieveSymmetricData
(QPair<QByteArray, QByteArray> &gemini,
 QByteArray &publicKey,
 QByteArray &symmetricKey,
 QByteArray &hashKey,
 QString &neighborOid,
 const QByteArray &cipherType,
 const QString &oid,
 spoton_crypt *crypt,
 bool *ok)
{
  if(!crypt)
    {
      if(ok)
	*ok = false;

      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT gemini, neighbor_oid, public_key, "
		      "gemini_hash_key "
		      "FROM friends_public_keys WHERE "
		      "OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  {
	    if(ok)
	      *ok = true;

	    if(query.next())
	      {
		size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		  (cipherType);

		if(symmetricKeyLength > 0)
		  {
		    if(!query.isNull(0))
		      gemini.first = crypt->decrypted
			(QByteArray::fromBase64(query.
						value(0).
						toByteArray()),
			 ok);

		    if(ok && *ok)
		      {
			if(!query.isNull(3))
			  gemini.second = crypt->decrypted
			    (QByteArray::fromBase64(query.
						    value(3).
						    toByteArray()),
			     ok);
		      }
		    else if(!ok)
		      if(!query.isNull(3))
			gemini.second = crypt->decrypted
			  (QByteArray::fromBase64(query.
						  value(3).
						  toByteArray()),
			   ok);

		    neighborOid = query.value(1).toString();
		    publicKey = query.value(2).toByteArray();
		    symmetricKey.resize
		      (static_cast<int> (symmetricKeyLength));
		    symmetricKey = spoton_crypt::strongRandomBytes
		      (symmetricKey.length());
		    hashKey.resize(static_cast<int> (symmetricKeyLength));
		    hashKey = spoton_crypt::strongRandomBytes
		      (hashKey.length());
		  }
		else
		  {
		    if(ok)
		      *ok  = false;

		    logError
		      ("spoton_misc::retrieveSymmetricData(): "
		       "cipherKeyLength() failure.");
		  }
	      }
	    else if(ok)
	      *ok = false;
	  }

	if(query.lastError().isValid())
	  {
	    if(ok)
	      *ok = false;
	  }
      }
    else if(ok)
      *ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

bool spoton_misc::isAcceptedParticipant(const QByteArray &publicKeyHash)
{
  QString connectionName("");
  int count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) "
		      "FROM friends_public_keys WHERE "
		      "neighbor_oid = -1 AND "
		      "public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    count = query.value(0).toInt();
      }
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

bool spoton_misc::isPrivateNetwork(const QHostAddress &address)
{
  bool isPrivate = false;

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    {
      QPair<QHostAddress, int> pair1
	(QHostAddress::parseSubnet("10.0.0.0/8"));
      QPair<QHostAddress, int> pair2
	(QHostAddress::parseSubnet("127.0.0.0/8"));
      QPair<QHostAddress, int> pair3
	(QHostAddress::parseSubnet("169.254.0.0/16"));
      QPair<QHostAddress, int> pair4
	(QHostAddress::parseSubnet("172.16.0.0/12"));
      QPair<QHostAddress, int> pair5
	(QHostAddress::parseSubnet("192.168.0.0/16"));

      isPrivate = address.isInSubnet(pair1) || address.isInSubnet(pair2) ||
	address.isInSubnet(pair3) || address.isInSubnet(pair4) ||
	address.isInSubnet(pair5);
    }
  else if(address.protocol() == QAbstractSocket::IPv6Protocol)
    {
      QPair<QHostAddress, int> pair1
	(QHostAddress::parseSubnet("::1/128"));
      QPair<QHostAddress, int> pair2
	(QHostAddress::parseSubnet("fc00::/7"));
      QPair<QHostAddress, int> pair3
	(QHostAddress::parseSubnet("fe80::/10"));

      isPrivate = address.isInSubnet(pair1) || address.isInSubnet(pair2) ||
	address.isInSubnet(pair3);
    }

  return isPrivate;
}

QPair<QByteArray, QByteArray> spoton_misc::findGeminiInCosmos
(const QByteArray &data, const QByteArray &hash, spoton_crypt *crypt)
{
  QPair<QByteArray, QByteArray> gemini;

  if(crypt && !hash.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = database(connectionName);

	db.setDatabaseName
	  (homePath() + QDir::separator() + "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);

	    if(query.exec("SELECT gemini, gemini_hash_key "
			  "FROM friends_public_keys WHERE "
			  "gemini IS NOT NULL AND "
			  "gemini_hash_key IS NOT NULL AND "
			  "key_type = 'chat' AND "
			  "neighbor_oid = -1"))
	      while(query.next())
		{
		  bool ok = true;

		  gemini.first = crypt->decrypted
		    (QByteArray::fromBase64(query.
					    value(0).
					    toByteArray()),
		     &ok);

		  if(ok)
		    gemini.second = crypt->decrypted
		      (QByteArray::fromBase64(query.
					      value(1).
					      toByteArray()),
		       &ok);

		  if(ok)
		    if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
		      {
			QByteArray computedHash
			  (spoton_crypt::keyedHash(data, gemini.second,
						   "sha512", &ok));

			if(ok)
			  if(!computedHash.isEmpty() && !hash.isEmpty() &&
			     spoton_crypt::memcmp(computedHash, hash))
			    break; // We have something!
		      }
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  return gemini;
}

void spoton_misc::moveSentMailToSentFolder(const QList<qint64> &oids,
					   spoton_crypt *crypt)
{
  QSettings settings;
  bool keep = settings.value("gui/saveCopy", true).toBool();

  if(keep)
    if(!crypt)
      return;

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(keep)
	  query.prepare("UPDATE folders SET status = ? WHERE "
			"OID = ?");
	else
	  query.prepare("DELETE FROM folders WHERE OID = ?");

	for(int i = 0; i < oids.size(); i++)
	  {
	    bool ok = true;

	    if(keep)
	      {
		query.bindValue
		  (0, crypt->encrypted(QObject::tr("Sent").toUtf8(), &ok).
		   toBase64());
		query.bindValue(1, oids.at(i));
	      }
	    else
	      query.bindValue(0, oids.at(i));

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::cleanupDatabases(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("UPDATE friends_public_keys SET status = 'offline'");

	/*
	** Delete asymmetric keys that were not completely shared.
	*/

	query.exec("DELETE FROM friends_public_keys WHERE "
		   "neighbor_oid <> -1");
	purgeSignatureRelationships(db);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM kernel_gui_server");
	query.exec("DELETE FROM kernel_statistics");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM listeners WHERE "
		   "status_control = 'deleted'");
	query.exec("DELETE FROM listeners_accounts WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("DELETE FROM listeners_accounts_consumed_authentications");
	query.exec("DELETE FROM listeners_allowed_ips WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("UPDATE listeners SET connections = 0, "
		   "external_ip_address = NULL, "
		   "status = 'offline'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSettings settings;
	QSqlQuery query(db);

	query.exec("DELETE FROM neighbors WHERE "
		   "status_control = 'deleted'");

	if(settings.
	   value("gui/keepOnlyUserDefinedNeighbors", false).toBool())
	  query.exec("DELETE FROM neighbors WHERE "
		     "status_control <> 'blocked' AND user_defined = 0");

	query.exec("UPDATE neighbors SET "
		   "account_authenticated = NULL, "
		   "bytes_read = 0, "
		   "bytes_written = 0, "
		   "external_ip_address = NULL, "
		   "is_encrypted = 0, "
		   "local_ip_address = NULL, "
		   "local_port = NULL, "
		   "ssl_session_cipher = NULL, "
		   "status = 'disconnected', "
		   "uptime = 0");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM transmitted WHERE "
		   "status_control = 'deleted'");
	query.exec("DELETE FROM transmitted_magnets WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
	query.exec("DELETE FROM transmitted_scheduled_pulses WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

QString spoton_misc::countryCodeFromName(const QString &country)
{
  QString code("");

  if(country == "United States")
    code = "us";

  return code;
}

QByteArray spoton_misc::publicKeyFromHash(const QByteArray &publicKeyHash)
{
  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = query.value(0).toByteArray();
      }
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::publicKeyFromSignaturePublicKeyHash
(const QByteArray &signaturePublicKeyHash)
{
  /*
  ** Gather the public key that's associated with the provided
  ** signature public key hash.
  */

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = (SELECT public_key_hash FROM "
		      "relationships_with_signatures WHERE "
		      "signature_public_key_hash = ?)");
	query.bindValue(0, signaturePublicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = query.value(0).toByteArray();
      }
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::signaturePublicKeyFromPublicKeyHash
(const QByteArray &publicKeyHash)
{
  /*
  ** Gather the signature public key that's associated with the
  ** provided public key hash.
  */

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = (SELECT signature_public_key_hash "
		      "FROM "
		      "relationships_with_signatures WHERE "
		      "public_key_hash = ?)");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = query.value(0).toByteArray();
      }
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

void spoton_misc::prepareUrlDatabases(void)
{
  QDir().mkdir(homePath() + QDir::separator() + "URLs");

  for(int i = 0; i < 26; i++)
    for(int j = 0; j < 26; j++)
      {
	QString connectionName("");

	{
	  QSqlDatabase db = database(connectionName);

	  db.setDatabaseName
	    (homePath() + QDir::separator() + "URLs" + QDir::separator() +
	     QString("urls_%1%2.db").
	     arg(static_cast<char> (i + 97)).
	     arg(static_cast<char> (j + 97)));

	  if(db.open())
	    {
	      QSqlQuery query(db);

	      query.exec("CREATE TABLE IF NOT EXISTS keywords ("
			 "keyword TEXT NOT NULL, "
			 "url_hash TEXT NOT NULL, "
			 "PRIMARY KEY (keyword, url_hash))");
	      query.exec("CREATE TABLE IF NOT EXISTS urls ("
			 "date_time_inserted TEXT NOT NULL, "
			 "description BLOB, "
			 "url_hash TEXT PRIMARY KEY NOT NULL, "
			 "title BLOB NOT NULL, "
			 "url BLOB NOT NULL)");
	    }

	  db.close();
	}

	QSqlDatabase::removeDatabase(connectionName);
      }
}

void spoton_misc::savePublishedNeighbor(const QHostAddress &address,
					const quint16 port,
					const QString &p_transport,
					const QString &statusControl,
					const QString &orientation,
					spoton_crypt *crypt)
{
  if(address.isNull())
    return;
  else if(!crypt)
    return;

  QString connectionName("");
  QString transport(p_transport.toLower().trimmed());

  if(!(transport == "tcp" || transport == "udp"))
    transport = "tcp";

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString country
	  (countryNameFromIPAddress(address.toString()));

	query.exec("INSERT INTO neighbors "
		   "(local_ip_address, "
		   "local_port, "
		   "protocol, "
		   "remote_ip_address, "
		   "remote_port, "
		   "scope_id, "
		   "status_control, "
		   "hash, "
		   "sticky, "
		   "country, "
		   "remote_ip_address_hash, "
		   "qt_country_hash, "
		   "user_defined, "
		   "proxy_hostname, "
		   "proxy_password, "
		   "proxy_port, "
		   "proxy_type, "
		   "proxy_username, "
		   "uuid, "
		   "echo_mode, "
		   "ssl_key_size, "
		   "certificate, "
		   "account_name, "
		   "account_password, "
		   "transport, "
		   "orientation) "
		   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));

	if(address.protocol() == QAbstractSocket::IPv4Protocol)
	  query.bindValue(2, "IPv4");
	else
	  query.bindValue(2, "IPv6");

	bool ok = true;

	query.bindValue
	  (3,
	   crypt->encrypted(address.toString().toLatin1(),
			    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (4,
	     crypt->
	     encrypted(QByteArray::number(port), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5,
	     crypt->encrypted(address.scopeId().toLatin1(),
			      &ok).toBase64());

	if(statusControl == "connected" || statusControl == "disconnected")
	  query.bindValue(6, statusControl);
	else
	  query.bindValue(6, "disconnected");

	if(ok)
	  query.bindValue
	    (7,
	     crypt->keyedHash((address.toString() +
			       QString::number(port) +
			       address.scopeId() +
			       transport).toLatin1(), &ok).
	     toBase64());

	query.bindValue(8, 1); // Sticky

	if(ok)
	  query.bindValue
	    (9, crypt->encrypted(country.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->keyedHash(address.toString().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (11, crypt->keyedHash(country.remove(" ").toLatin1(), &ok).
	     toBase64());

	query.bindValue(12, 1);

	QString proxyHostname("");
	QString proxyPassword("");
	QString proxyPort("1");
	QString proxyType(QString::number(QNetworkProxy::NoProxy));
	QString proxyUsername("");

	if(ok)
	  query.bindValue
	    (13, crypt->encrypted(proxyHostname.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, crypt->encrypted(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (15, crypt->encrypted(proxyPort.toLatin1(),
				  &ok).toBase64());

	if(ok)
	  query.bindValue
	    (16, crypt->encrypted(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, crypt->encrypted(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (18, crypt->
	     encrypted("{00000000-0000-0000-0000-000000000000}", &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (19, crypt->encrypted("full", &ok).toBase64());

	if(ok)
	  {
	    if(transport == "tcp")
	      {
		QSettings settings;
		QString error("");
		int keySize = 2048;

		keySize = settings.value
		  ("gui/publishedKeySize", "2048").toInt(&ok);

		if(!ok)
		  keySize = 2048;
		else if(!(keySize == 2048 ||
			  keySize == 3072 ||
			  keySize == 4096 ||
			  keySize == 8192))
		  keySize = 2048;

		query.bindValue(20, keySize);
	      }
	    else
	      query.bindValue(20, 0);
	  }

	if(ok)
	  query.bindValue
	    (21, crypt->encrypted(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (22, crypt->encrypted(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (23, crypt->encrypted(QByteArray(), &ok).toBase64());

	if(ok)
	  {
	    if(transport == "tcp" || transport == "udp")
	      query.bindValue
		(24, crypt->encrypted(transport.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(24, crypt->encrypted("tcp", &ok).toBase64());
	  }

	if(ok)
	  {
	    if(orientation == "packet" || orientation == "stream")
	      query.bindValue
		(25, crypt->encrypted(orientation.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(25, crypt->encrypted("packet", &ok).toBase64());
	  }

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::purgeSignatureRelationships(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);

  /*
  ** Delete relationships that do not have corresponding entries
  ** in the friends_public_keys table.
  */

  query.exec("DELETE FROM relationships_with_signatures WHERE "
	     "public_key_hash NOT IN "
	     "(SELECT public_key_hash FROM friends_public_keys WHERE "
	     "key_type NOT LIKE '%signature')");

  /*
  ** Delete signature public keys from friends_public_keys that
  ** do not have relationships.
  */

  query.exec("DELETE FROM friends_public_keys WHERE "
	     "key_type LIKE '%signature' AND public_key_hash NOT IN "
	     "(SELECT signature_public_key_hash FROM "
	     "relationships_with_signatures)");
}

void spoton_misc::correctSettingsContainer(QHash<QString, QVariant> settings)
{
  /*
  ** Attempt to correct flawed configuration settings.
  */

  QString str("");
  bool ok = true;
  int integer = 0;

  integer = qAbs(settings.value("gui/congestionCost", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;
  else if(integer < 1000)
    integer = 10000;

  settings.insert("gui/congestionCost", integer);
  integer = qAbs(settings.value("gui/emailRetrievalInterval",
				5).toInt(&ok));

  if(!ok)
    integer = 5;
  else if(integer > 60)
    integer = 5;

  settings.insert("gui/emailRetrievalInterval", integer);
  integer = qAbs(settings.value("gui/gcryctl_init_secmem", 65536).toInt(&ok));

  if(!ok)
    integer = 65536;
  else if(integer < 65536)
    integer = 65536;

  settings.insert("gui/gcryctl_init_secmem", integer);
  integer = settings.value("gui/guiExternalIpInterval", -1).toInt(&ok);

  if(!ok)
    integer = -1;
  else if(!(integer == -1 || integer == 30 || integer == 60))
    integer = -1;

  settings.insert("gui/guiExternalIpInterval", integer);
  str = settings.value("gui/iconSet", "nouve").toString().trimmed();

  if(!(str == "nouve" || str == "nuvola"))
    str = "nouve";

  settings.insert("gui/iconSet", str);
  integer = qAbs(settings.value("gui/iterationCount", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;
  else if(integer < 10000)
    integer = 10000;

  settings.insert("gui/iterationCount", integer);
  str = settings.value("gui/kernelCipherType").toString().trimmed();

  if(!(str == "aes256" || str == "camellia256" ||
       str == "gost28147" || str == "randomized" ||
       str == "serpent256" || str == "twofish"))
    str = "aes256";

  settings.insert("gui/kernelCipherType", str);
  integer = settings.value("gui/kernelExternalIpInterval", -1).toInt(&ok);

  if(!ok)
    integer = -1;
  else if(!(integer == -1 || integer == 30 || integer == 60))
    integer = -1;

  settings.insert("gui/kernelExternalIpInterval", integer);
  integer = qAbs(settings.value("gui/kernelKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096 || integer == 8192))
    integer = 2048;

  settings.insert("gui/kernelKeySize", integer);
  integer = qAbs(settings.value("gui/keySize", 3072).toInt(&ok));

  if(!ok)
    integer = 3072;
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096 || integer == 7680 ||
	    integer == 8192 || integer == 15360))
    integer = 3072;

  settings.insert("gui/keySize", integer);
  integer = qAbs(settings.value("gui/publishedKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096 || integer == 8192))
    integer = 2048;

  settings.insert("gui/publishedKeySize", integer);
  integer = qAbs(settings.value("gui/maxMosaicSize", 512).toInt(&ok));

  if(!ok)
    integer = 512;
  else if(integer < 1 || integer > 5000)
    integer = 512;

  settings.insert("gui/maxMosaicSize", integer);
  integer = qAbs(settings.value("gui/saltLength", 512).toInt(&ok));

  if(!ok)
    integer = 512;
  else if(integer < 512)
    integer = 512;

  settings.insert("gui/saltLength", integer);
  integer = qAbs(settings.value("kernel/gcryctl_init_secmem",
				65536).toInt(&ok));

  if(!ok)
    integer = 65536;
  else if(integer < 65536)
    integer = 65536;

  settings.insert("kernel/gcryctl_init_secmem", integer);
  integer = qAbs
    (settings.value("kernel/server_account_verification_window_msecs",
		    15000).toInt(&ok));

  if(!ok)
    integer = 15000;

  settings.insert
    ("kernel/server_account_verification_window_msecs", integer);
}

QSqlDatabase spoton_misc::database(QString &connectionName)
{
  QSqlDatabase db;
  quint64 dbId = 0;

  s_dbMutex.lock();
  dbId = s_dbId += 1;
  s_dbMutex.unlock();
  db = QSqlDatabase::addDatabase
    ("QSQLITE", QString("spoton_database_%1").arg(dbId));
  connectionName = db.connectionName();
  return db;
}

void spoton_misc::enableLog(const bool state)
{
  s_enableLog = state;
}

int spoton_misc::participantCount(const QString &keyType)
{
  QString connectionName("");
  int count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM friends_public_keys "
		      "WHERE key_type = ? AND neighbor_oid = -1");
	query.bindValue(0, keyType);

	if(query.exec())
	  if(query.next())
	    count = query.value(0).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count;
}

bool spoton_misc::isValidSignature(const QByteArray &data,
				   const QByteArray &publicKeyHash,
				   const QByteArray &signature)
{
  /*
  ** We must locate the signature public key that's associated with the
  ** provided public key hash. Remember, publicKeyHash is the hash of the
  ** non-signature public key.
  */

  QByteArray publicKey(signaturePublicKeyFromPublicKeyHash(publicKeyHash));

  if(publicKey.isEmpty())
    return false;

  return spoton_crypt::isValidSignature(data, publicKey, signature);
}

bool spoton_misc::isAcceptedIP(const QHostAddress &address,
			       const qint64 id,
			       spoton_crypt *crypt)
{
  if(!crypt)
    return false;

  QString connectionName("");
  int count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);

	query.prepare("SELECT COUNT(*) FROM listeners_allowed_ips "
		      "WHERE ip_address_hash IN (?, ?) AND "
		      "listener_oid = ?");
	query.bindValue(0, crypt->keyedHash(address.toString().
					    toLatin1(), &ok).
			toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash("Any", &ok).toBase64());

	query.bindValue(2, id);

	if(ok)
	  if(query.exec())
	    if(query.next())
	      count = query.value(0).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

bool spoton_misc::authenticateAccount(QByteArray &name,
				      QByteArray &password,
				      const qint64 listenerOid,
				      const QByteArray &saltedCredentials,
				      const QByteArray &salt,
				      spoton_crypt *crypt)
{
  if(!crypt)
    {
      name.clear();
      password.clear();
      return false;
    }

  QString connectionName("");
  bool found = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool exists = false;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM "
		      "listeners_accounts_consumed_authentications "
		      "WHERE data = ? AND listener_oid = ?");
	query.bindValue(0, saltedCredentials.toBase64());
	query.bindValue(1, listenerOid);

	if(query.exec())
	  if(query.next())
	    exists = query.value(0).toInt() > 0;

	if(!exists)
	  {
	    QByteArray salted;
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT account_name, account_password "
			  "FROM listeners_accounts WHERE "
			  "listener_oid = ?");
	    query.bindValue(0, listenerOid);

	    if(query.exec())
	      while(query.next())
		{
		  bool ok = true;

		  name = crypt->decrypted
		    (QByteArray::fromBase64(query.value(0).
					    toByteArray()),
		     &ok);

		  if(ok)
		    password = crypt->decrypted
		      (QByteArray::fromBase64(query.value(1).
					      toByteArray()),
		       &ok);

		  if(ok)
		    salted = spoton_crypt::saltedValue
		      ("sha512", name + password +
		       QDateTime::currentDateTime().toUTC().
		       toString("MMddyyyyhhmm").toLatin1(), salt, &ok);

		  if(ok)
		    if(!salted.isEmpty() && !saltedCredentials.isEmpty() &&
		       spoton_crypt::memcmp(salted, saltedCredentials))
		      {
			found = true;
			break;
		      }

		  if(ok)
		    salted = spoton_crypt::saltedValue
		      ("sha512", name + password +
		       QDateTime::currentDateTime().toUTC().addSecs(60).
		       toString("MMddyyyyhhmm").toLatin1(), salt, &ok);

		  if(ok)
		    if(!salted.isEmpty() && !saltedCredentials.isEmpty() &&
		       spoton_crypt::memcmp(salted, saltedCredentials))
		      {
			found = true;
			break;
		      }
		}

	    if(found)
	      {
		/*
		** Record the authentication data.
		*/

		QSqlQuery query(db);
		bool ok = true;

		query.prepare("DELETE FROM listeners_accounts "
			      "WHERE account_name_hash = ? AND "
			      "listener_oid = ? AND one_time_account = 1");
		query.bindValue
		  (0, crypt->keyedHash(name, &ok).toBase64());
		query.bindValue(1, listenerOid);

		if(ok)
		  query.exec();

		/*
		** I think we only wish to create an entry in
		** listeners_accounts_consumed_authentications if
		** the discovered account is not temporary.
		*/

		if(!ok || query.numRowsAffected() <= 0)
		  {
		    query.prepare
		      ("INSERT OR REPLACE INTO "
		       "listeners_accounts_consumed_authentications "
		       "(data, insert_date, listener_oid) "
		       "VALUES (?, ?, ?)");
		    query.bindValue(0, saltedCredentials.toBase64());
		    query.bindValue
		      (1, QDateTime::currentDateTime().toString(Qt::ISODate));
		    query.bindValue(2, listenerOid);
		    query.exec();
		  }
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!found)
    {
      name.clear();
      password.clear();
    }

  return found;
}

bool spoton_misc::allParticipantsHaveGeminis(void)
{
  QString connectionName("");
  int count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM friends_public_keys WHERE "
		      "gemini IS NULL AND gemini_hash_key IS NULL AND "
		      "neighbor_oid = -1"))
	  if(query.next())
	    count = query.value(0).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  return count == 0;
}

bool spoton_misc::isValidBuzzMagnetData(const QByteArray &data)
{
  QList<QByteArray> list(data.trimmed().split('\n'));
  bool valid = false;

  for(int i = 0; i < 7; i++)
    {
      QByteArray str(QByteArray::fromBase64(list.value(i).trimmed()));

      if(i == 0) // Channel
	{
	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 1) // Iteration Count
	{
	  if(str.toInt() < 10000)
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 2) // Channel Salt
	{
	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 3) // Channel Type
	{
	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 4) // Hash
	{
	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 5) // Hash Type
	{
	  if(!spoton_crypt::hashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 6) // Urn
	{
	  if(str != "urn:buzz")
	    {
	      valid = false;
	      goto done_label;
	    }
	}
    }

  valid = true;

 done_label:
  return valid;
}

bool spoton_misc::isValidBuzzMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.trimmed().startsWith("magnet:?"))
    list = magnet.trimmed().mid(qstrlen("magnet:?")).split('&');
  else
    goto done_label;

  while(!list.isEmpty())
    {
      QString str(list.takeFirst().trimmed());

      if(str.startsWith("ct="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("rn="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("ht="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::hashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("hk="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("xf="))
	{
	  str.remove(0, 3);

	  if(str.toInt() < 10000)
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("xs="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:buzz")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
    }

  if(tokens == 7)
    valid = true;

 done_label:
  return valid;
}

bool spoton_misc::isValidStarBeamMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.trimmed().startsWith("magnet:?"))
    list = magnet.trimmed().mid(qstrlen("magnet:?")).split('&');
  else
    goto done_label;

  while(!list.isEmpty())
    {
      QString str(list.takeFirst().trimmed());

      if(str.startsWith("ct="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("ek="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("ht="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::hashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("mk="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:starbeam")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
    }

  if(tokens == 5)
    valid = true;

 done_label:
  return valid;
}
