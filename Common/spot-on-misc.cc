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

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QLocale>
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
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

extern "C"
{
#include <signal.h>
}

QReadWriteLock spoton_misc::s_dbMutex;
QReadWriteLock spoton_misc::s_enableLogMutex;
bool spoton_misc::s_enableLog = false;
quint64 spoton_misc::s_dbId = 0;

QString spoton_misc::homePath(void)
{
  QByteArray homepath(qgetenv("SPOTON_HOME"));

  if(homepath.isEmpty())
#ifdef Q_OS_WIN32
    return QDir::currentPath() + QDir::separator() + ".spot-on";
#else
    return QDir::homePath() + QDir::separator() + ".spot-on";
#endif
  else
    return homepath.constData();
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
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "folders_attachment ("
		   "data BLOB NOT NULL, "
		   "folders_oid INTEGER NOT NULL, "
		   "name TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS institutions ("
		   "cipher_type TEXT NOT NULL, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** Hash of the
						      ** name.
						      */
		   "hash_type TEXT NOT NULL, "
		   "name TEXT NOT NULL, "
		   "postal_address TEXT NOT NULL)");
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
	   "key_type TEXT NOT NULL, "
	   "key_type_hash TEXT NOT NULL, " // Keyed hash.
	   "name TEXT NOT NULL DEFAULT 'unknown', "
	   "public_key BLOB NOT NULL, "
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
	   "gemini_hash_key TEXT DEFAULT NULL, "
	   "name_changed_by_user INTEGER NOT NULL DEFAULT 0)");
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
		   "id TEXT NOT NULL, "
		   "id_hash TEXT PRIMARY KEY NOT NULL, " // Keyed hash.
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
		   "ssl_control_string TEXT NOT NULL DEFAULT "
		   "'HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH', "
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
		   "PRIMARY KEY (listener_oid, account_name_hash))");
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "listeners_accounts_consumed_authentications ("
		   "data TEXT NOT NULL, "
		   "insert_date TEXT NOT NULL DEFAULT 'now', "
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (listener_oid, data))");
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "listeners_adaptive_echo_tokens ("
		   "token TEXT NOT NULL, " /*
					   ** Please
					   ** note that the table
					   ** houses both encryption
					   ** and hash keys. Apologies
					   ** for violating some
					   ** database principles.
					   */
		   "token_hash TEXT PRIMARY KEY NOT NULL, " /*
							    ** Keyed hash of
							    ** the token and
							    ** the token type.
							    */
		   "token_type TEXT NOT NULL)"); /*
						 ** The token_type contains
						 ** both cipher and hash
						 ** algorithm information.
						 */
	query.exec("CREATE TABLE IF NOT EXISTS listeners_allowed_ips ("
		   "ip_address TEXT NOT NULL, "
		   "ip_address_hash TEXT NOT NULL, " // Keyed hash.
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (ip_address_hash, listener_oid))");
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
		   "ssl_control_string TEXT NOT NULL DEFAULT "
		   "'HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH', "
		   "ssl_session_cipher TEXT, "
		   "ssl_required INTEGER NOT NULL DEFAULT 1, "
		   "account_name TEXT NOT NULL, "
		   "account_password TEXT NOT NULL, "
		   "account_authenticated TEXT, "
		   "transport TEXT NOT NULL, "
		   "orientation TEXT NOT NULL, "
		   "motd TEXT NOT NULL DEFAULT 'Welcome to Spot-On.', "
		   "ae_token TEXT, " /*
				     ** Please
				     ** note that the table
				     ** houses both encryption
				     ** and hash keys of adaptive
				     ** echo tokens. Apologies
				     ** for violating some
				     ** database principles.
				     */
		   "ae_token_type TEXT, " /*
					  ** The ae_token_type contains
					  ** both cipher and hash
					  ** algorithm information.
					  */
		   "priority INTEGER NOT NULL DEFAULT 4)"). /*
							    ** High
							    ** priority.
							    */
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH));
	query.exec
	  ("ALTER TABLE neighbors ADD COLUMN priority "
	   "INTEGER NOT NULL DEFAULT 4");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS poptastic ("
		   "in_authentication TEXT NOT NULL, "
		   "in_method TEXT NOT NULL, "
		   "in_password TEXT NOT NULL, "
		   "in_server_address TEXT NOT NULL, "
		   "in_server_port TEXT NOT NULL, "
		   "in_ssltls TEXT NOT NULL, "
		   "in_username TEXT NOT NULL, "
		   "out_authentication TEXT NOT NULL, "
		   "out_method TEXT NOT NULL, "
		   "out_password TEXT NOT NULL, "
		   "out_server_address TEXT NOT NULL, "
		   "out_server_port TEXT NOT NULL, "
		   "out_ssltls TEXT NOT NULL, "
		   "out_username TEXT NOT NULL, "
		   "proxy_enabled TEXT NOT NULL, "
		   "proxy_password TEXT NOT NULL, "
		   "proxy_server_address TEXT NOT NULL, "
		   "proxy_server_port TEXT NOT NULL, "
		   "proxy_type TEXT NOT NULL, "
		   "proxy_username TEXT NOT NULL)");
	query.exec("CREATE TRIGGER IF NOT EXISTS "
		   "poptastic_trigger "
		   "BEFORE INSERT ON poptastic "
		   "BEGIN "
		   "DELETE FROM poptastic; "
		   "END");
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
		   "locked INTEGER NOT NULL DEFAULT 0, "
		   "pulse_size TEXT NOT NULL, "
		   "total_size TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS received_novas ("
		   "nova TEXT NOT NULL, " /*
					  ** Please
					  ** note that the table
					  ** houses both encryption
					  ** and hash keys. Apologies
					  ** for violating some
					  ** database principles.
					  */
		   "nova_hash TEXT PRIMARY KEY NOT NULL)"); // Keyed hash.
	query.exec("CREATE TABLE IF NOT EXISTS transmitted ("
		   "file TEXT NOT NULL, "
		   "hash TEXT NOT NULL, " /*
					  ** Keyed hash of the file.
					  */
		   "missing_links BLOB NOT NULL, "
		   "mosaic TEXT PRIMARY KEY NOT NULL, "
		   "nova TEXT NOT NULL, " /*
					  ** Please
					  ** note that the table
					  ** houses both encryption
					  ** and hash keys. Apologies
					  ** for violating some
					  ** database principles.
					  */
		   "position TEXT NOT NULL, "
		   "pulse_size TEXT NOT NULL, "
		   "status_control TEXT NOT NULL DEFAULT 'paused', "
		   "total_size TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS transmitted_magnets ("
		   "magnet BLOB NOT NULL, "
		   "magnet_hash TEXT NOT NULL, " // Keyed hash.
		   "transmitted_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (magnet_hash, transmitted_oid))");
	query.exec("CREATE TABLE IF NOT EXISTS transmitted_scheduled_pulses ("
		   "position TEXT NOT NULL, "
		   "position_hash TEXT NOT NULL, " // Keyed hash.
		   "transmitted_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (position_hash, transmitted_oid))");
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
  QReadLocker locker(&s_enableLogMutex);

  if(!s_enableLog)
    return;

  locker.unlock();

  if(error.trimmed().isEmpty())
    return;

  QFile file(homePath() + QDir::separator() + "error_log.dat");

  if(file.size() > 512 * 1024)
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
      QString eol("\n");
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
  QHostAddress address(ipAddress);
  QSettings settings;
  QString fileName("");

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    fileName = settings.value("gui/geoipPath4", "GeoIP.dat").toString();
  else
    fileName = settings.value("gui/geoipPath6", "GeoIP.dat").toString();

  fileInfo.setFile(fileName);

  if(fileInfo.isReadable())
    {
      gi = GeoIP_open(fileName.toUtf8().constData(), GEOIP_MEMORY_CACHE);

      if(gi)
	code = GeoIP_country_code_by_addr
	  (gi, ipAddress.toLatin1().constData());
      else
	logError("spoton_misc::countryCodeFromIPAddress(): gi is zero.");
    }

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
  QHostAddress address(ipAddress);
  QSettings settings;
  QString fileName("");

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    fileName = settings.value("gui/geoipPath4", "GeoIP.dat").toString();
  else
    fileName = settings.value("gui/geoipPath6", "GeoIP.dat").toString();

  fileInfo.setFile(fileName);

  if(fileInfo.isReadable())
    {
      gi = GeoIP_open(fileName.toUtf8().constData(), GEOIP_MEMORY_CACHE);

      if(gi)
	country = GeoIP_country_name_by_addr
	  (gi, ipAddress.toLatin1().constData());
      else
	logError("spoton_misc::countryNameFromIPAddress(): gi is zero.");
    }

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
	      (1, crypt->encryptedThenHashed
	       (variants.value(0).toByteArray(), &ok).
	       toBase64());

	    if(ok)
	      query1.bindValue
		(2, crypt->keyedHash(variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.bindValue
		(3, crypt->encryptedThenHashed
		 (variants.value(1).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.bindValue
		(4, crypt->encryptedThenHashed
		 (variants.value(2).toByteArray(), &ok).
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
				       const QSqlDatabase &db,
				       spoton_crypt *crypt)
{
  if(!db.isOpen())
    return false;
  else if(!crypt)
    return false;

  QSqlQuery query(db);
  bool ok = true;

  query.prepare("INSERT OR REPLACE INTO friends_public_keys "
		"(gemini, gemini_hash_key, key_type, key_type_hash, "
		"name, public_key, public_key_hash, "
		"neighbor_oid, last_status_update) "
		"VALUES ((SELECT gemini FROM friends_public_keys WHERE "
		"public_key_hash = ?), "
		"(SELECT gemini_hash_key FROM friends_public_keys WHERE "
		"public_key_hash = ?), "
		"?, ?, ?, ?, ?, ?, ?)");
  query.bindValue(0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue(1, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue(2, crypt->encryptedThenHashed(keyType, &ok).toBase64());

  if(ok)
    query.bindValue(3, crypt->keyedHash(keyType, &ok).toBase64());

  if(keyType == "chat" || keyType == "email" || keyType == "poptastic" ||
     keyType == "rosetta" || keyType == "url")
    {
      if(ok)
	{
	  if(name.isEmpty())
	    {
	      if(keyType == "poptastic")
		query.bindValue
		  (4, crypt->
		   encryptedThenHashed(QByteArray("unknown@unknown.org"),
				       &ok).toBase64());
	      else
		query.bindValue
		  (4, crypt->
		   encryptedThenHashed(QByteArray("unknown"),
				       &ok).toBase64());
	    }
	  else
	    query.bindValue
	      (4, crypt->
	       encryptedThenHashed(name.
				   mid(0, spoton_common::
				       NAME_MAXIMUM_LENGTH),
				   &ok).toBase64());
	}
    }
  else if(ok) // Signature keys will be labeled as their type.
    query.bindValue(4, crypt->encryptedThenHashed(keyType, &ok).toBase64());

  if(ok)
    query.bindValue
      (5, crypt->encryptedThenHashed(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue
      (6, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  query.bindValue(7, neighborOid);
  query.bindValue
    (8, QDateTime::currentDateTime().toString(Qt::ISODate));

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
 QString &receiverName,
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
		      "gemini_hash_key, name "
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
		      gemini.first = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(0).
						toByteArray()),
			 ok);

		    if(ok && *ok)
		      {
			if(!query.isNull(3))
			  gemini.second = crypt->decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(3).
						    toByteArray()),
			     ok);
		      }
		    else if(!ok)
		      if(!query.isNull(3))
			gemini.second = crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(3).
						  toByteArray()),
			   ok);

		    neighborOid = query.value(1).toString();

		    if(ok && *ok)
		      publicKey = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(2).
						toByteArray()),
			 ok);
		    else if(!ok)
		      publicKey = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(2).
						toByteArray()),
			 ok);

		    if(ok && *ok)
		      receiverName = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(4).
						toByteArray()),
			 ok);
		    else if(!ok)
		      receiverName = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(4).
						toByteArray()),
			 ok);

		    symmetricKey.resize
		      (static_cast<int> (symmetricKeyLength));
		    symmetricKey = spoton_crypt::strongRandomBytes
		      (symmetricKey.length());
		    hashKey.resize
		      (spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
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

bool spoton_misc::isAcceptedParticipant(const QByteArray &publicKeyHash,
					const QString &keyType,
					spoton_crypt *crypt)
{
  if(!crypt)
    return false;

  QString connectionName("");
  qint64 count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND "
		      "neighbor_oid = -1 AND "
		      "public_key_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(keyType.toLatin1(), &ok).toBase64());
	query.bindValue(1, publicKeyHash.toBase64());

	if(ok && query.exec())
	  if(query.next())
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

bool spoton_misc::isPrivateNetwork(const QHostAddress &address)
{
  bool isPrivate = false;

  if(address.isNull())
    return isPrivate;
  else if(address.protocol() == QAbstractSocket::IPv4Protocol)
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
	    bool ok = true;

	    query.setForwardOnly(true);
	    query.prepare("SELECT gemini, gemini_hash_key "
			  "FROM friends_public_keys WHERE "
			  "gemini IS NOT NULL AND "
			  "gemini_hash_key IS NOT NULL AND "
			  "key_type_hash IN (?, ?) AND "
			  "neighbor_oid = -1");
	    query.bindValue(0, crypt->keyedHash(QByteArray("chat"), &ok).
			    toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash(QByteArray("poptastic"), &ok).
		 toBase64());

	    if(ok && query.exec())
	      while(query.next())
		{
		  bool ok = true;

		  gemini.first = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).
					    toByteArray()),
		     &ok);

		  if(ok)
		    gemini.second = crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).
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

		  gemini.first.clear();
		  gemini.second.clear();
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
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM folders WHERE OID = ?");
	  }

	for(int i = 0; i < oids.size(); i++)
	  {
	    bool ok = true;

	    if(keep)
	      {
		query.bindValue
		  (0, crypt->encryptedThenHashed(QByteArray("Sent"),
						 &ok).toBase64());
		query.bindValue(1, oids.at(i));
	      }
	    else
	      query.bindValue(0, oids.at(i));

	    if(ok)
	      if(query.exec())
		if(!keep)
		  {
		    QSqlQuery query(db);

		    query.exec("PRAGMA secure_delete = ON");
		    query.prepare
		      ("DELETE FROM folders_attachment WHERE "
		       "folders_oid = ?");
		    query.bindValue(0, oids.at(i));
		    query.exec();
		  }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::cleanupDatabases(spoton_crypt *crypt)
{
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("UPDATE friends_public_keys SET status = 'offline' "
		   "WHERE status <> 'offline'");

	/*
	** Delete asymmetric keys that were not completely shared.
	*/

	query.exec("DELETE FROM friends_public_keys WHERE "
		   "neighbor_oid <> -1");
	purgeSignatureRelationships(db, crypt);
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

	query.exec("PRAGMA secure_delete = ON");
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

	query.exec("PRAGMA secure_delete = ON");
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

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM neighbors WHERE "
		   "status_control = 'deleted'");

	if(settings.
	   value("gui/keepOnlyUserDefinedNeighbors", true).toBool())
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

	query.exec("PRAGMA secure_delete = ON");
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

QByteArray spoton_misc::publicKeyFromHash(const QByteArray &publicKeyHash,
					  spoton_crypt *crypt)
{
  if(!crypt)
    return QByteArray();

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::publicKeyFromSignaturePublicKeyHash
(const QByteArray &signaturePublicKeyHash, spoton_crypt *crypt)
{
  if(!crypt)
    return QByteArray();

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
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = (SELECT public_key_hash FROM "
		      "relationships_with_signatures WHERE "
		      "signature_public_key_hash = ?)");
	query.bindValue(0, signaturePublicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::signaturePublicKeyFromPublicKeyHash
(const QByteArray &publicKeyHash, spoton_crypt *crypt)
{
  if(!crypt)
    return QByteArray();

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
	bool ok = true;

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
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
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
  QString transport(p_transport.toLower());

#ifdef SPOTON_SCTP_ENABLED
  if(!(transport == "sctp" || transport == "tcp" || transport == "udp"))
    transport = "tcp";
#else
  if(!(transport == "tcp" || transport == "udp"))
    transport = "tcp";
#endif

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString country
	  (countryNameFromIPAddress(address.toString()));
	bool ok = true;

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
		   "orientation, "
		   "ssl_control_string) "
		   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));

	if(address.protocol() == QAbstractSocket::IPv4Protocol)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed("IPv4", &ok).toBase64());
	else
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed("IPv6", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3,
	     crypt->encryptedThenHashed(address.toString().toLatin1(),
					&ok).toBase64());

	if(ok)
	  query.bindValue
	    (4,
	     crypt->
	     encryptedThenHashed(QByteArray::number(port), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5,
	     crypt->encryptedThenHashed(address.scopeId().toLatin1(),
					&ok).toBase64());

	if(statusControl == "connected" || statusControl == "disconnected")
	  query.bindValue(6, statusControl);
	else
	  query.bindValue(6, "disconnected");

	if(ok)
	  /*
	  ** We do not have proxy information.
	  */

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
	    (9, crypt->encryptedThenHashed(country.toLatin1(),
					   &ok).toBase64());

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
	    (13, crypt->encryptedThenHashed(proxyHostname.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, crypt->encryptedThenHashed(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (15, crypt->encryptedThenHashed(proxyPort.toLatin1(),
					    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (16, crypt->encryptedThenHashed(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, crypt->encryptedThenHashed(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (18, crypt->
	     encryptedThenHashed("{00000000-0000-0000-0000-000000000000}",
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (19, crypt->encryptedThenHashed("full", &ok).toBase64());

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
	    (21, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (22, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (23, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  {
#ifdef SPOTON_SCTP_ENABLED
	    if(transport == "sctp" ||
	       transport == "tcp" ||
	       transport == "udp")
#else
	    if(transport == "tcp" || transport == "udp")
#endif
	      query.bindValue
		(24, crypt->encryptedThenHashed(transport.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(24, crypt->encryptedThenHashed("tcp", &ok).toBase64());
	  }

	if(ok)
	  {
	    if(orientation == "packet" || orientation == "stream")
	      query.bindValue
		(25, crypt->encryptedThenHashed(orientation.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(25, crypt->encryptedThenHashed("packet", &ok).toBase64());
	  }

	if(transport == "tcp")
	  query.bindValue
	    (26, "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH");
	else
	  query.bindValue(26, "N/A");

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::purgeSignatureRelationships(const QSqlDatabase &db,
					      spoton_crypt *crypt)
{
  if(!crypt)
    return;
  else if(!db.isOpen())
    return;

  QList<QByteArray> list;

  list << "chat"
       << "email"
       << "poptastic"
       << "rosetta"
       << "url";

  for(int i = 0; i < list.size(); i++)
    {
      QSqlQuery query(db);
      bool ok = true;

      /*
      ** Delete relationships that do not have corresponding entries
      ** in the friends_public_keys table.
      */

      query.exec("PRAGMA secure_delete = ON");
      query.prepare("DELETE FROM relationships_with_signatures WHERE "
		    "public_key_hash NOT IN "
		    "(SELECT public_key_hash FROM friends_public_keys WHERE "
		    "key_type_hash <> ?)");
      query.bindValue
	(0, crypt->keyedHash(list.at(i) + "-signature", &ok).toBase64());

      if(ok)
	query.exec();

      /*
      ** Delete signature public keys from friends_public_keys that
      ** do not have relationships.
      */

      query.prepare
	("DELETE FROM friends_public_keys WHERE "
	 "key_type_hash = ? AND public_key_hash NOT IN "
	 "(SELECT signature_public_key_hash FROM "
	 "relationships_with_signatures)");

      if(ok)
	query.bindValue
	  (0, crypt->keyedHash(list.at(i) + "-signature", &ok).toBase64());

      if(ok)
	query.exec();
    }
}

void spoton_misc::correctSettingsContainer(QHash<QString, QVariant> settings)
{
  /*
  ** Attempt to correct flawed configuration settings.
  */

  QString str("");
  QStringList list;
  bool ok = true;
  double rational = 0.00;
  int integer = 0;

  integer = qAbs(settings.value("gui/congestionCost", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;
  else if(integer < 1000 || integer > 65535)
    integer = 10000;

  settings.insert("gui/congestionCost", integer);
  integer = qAbs(settings.value("gui/emailRetrievalInterval",
				5).toInt(&ok));

  if(!ok)
    integer = 5;
  else if(integer < 5 || integer > 60)
    integer = 5;

  settings.insert("gui/emailRetrievalInterval", integer);
  integer = qAbs(settings.value("gui/gcryctl_init_secmem", 65536).toInt(&ok));

  if(!ok)
    integer = 65536;
  else if(integer < 65536 || integer > 999999999)
    integer = 65536;

  settings.insert("gui/gcryctl_init_secmem", integer);
  integer = settings.value("gui/guiExternalIpInterval", -1).toInt(&ok);

  if(!ok)
    integer = -1;
  else if(!(integer == -1 || integer == 30 || integer == 60))
    integer = -1;

  settings.insert("gui/guiExternalIpInterval", integer);
  str = settings.value("gui/hashType").toString();

  if(!(str == "sha512" || str == "stribog512" ||
       str == "whirlpool"))
    str = "sha512";

  settings.insert("gui/hashType", str);
  str = settings.value("gui/iconSet", "nouve").toString();

  if(!(str == "everaldo" || str == "nouve" || str == "nuvola"))
    str = "nouve";

  settings.insert("gui/iconSet", str);
  integer = qAbs(settings.value("gui/iterationCount", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;
  else if(integer < 10000 || integer > 999999999)
    integer = 10000;

  settings.insert("gui/iterationCount", integer);
  str = settings.value("gui/kernelCipherType").toString();

  if(!(str == "aes256" || str == "camellia256" ||
       str == "serpent256" || str == "twofish"))
    str = "aes256";

  settings.insert("gui/kernelCipherType", str);
  integer = settings.value("gui/kernelExternalIpInterval", -1).toInt(&ok);

  if(!ok)
    integer = -1;
  else if(!(integer == -1 || integer == 30 || integer == 60))
    integer = -1;

  settings.insert("gui/kernelExternalIpInterval", integer);
  str = settings.value("gui/kernelHashType").toString();

  if(!(str == "sha512" || str == "stribog512" || str == "whirlpool"))
    str = "sha512";

  settings.insert("gui/kernelHashType", str);
  integer = qAbs(settings.value("gui/kernelKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096 || integer == 8192))
    integer = 2048;

  settings.insert("gui/kernelKeySize", integer);
  integer = qAbs(settings.value("gui/limitConnections", 10).toInt(&ok));

  if(!ok)
    integer = 10;
  else if(integer <= 0 || integer > 50)
    integer = 10;

  settings.insert("gui/limitConnections", integer);
  integer = qAbs(settings.value("gui/maximumEmailFileSize", 100).toInt(&ok));

  if(!ok)
    integer = 100;
  else if(integer < 1 || integer > 5000)
    integer = 100;

  settings.insert("gui/maximumEmailFileSize", integer);
  integer = qAbs(settings.value("gui/postofficeDays", 1).toInt(&ok));

  if(!ok)
    integer = 1;
  else if(integer < 1 || integer > 366)
    integer = 1;

  settings.insert("gui/postofficeDays", integer);
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
  else if(integer < 512 || integer > 999999999)
    integer = 512;

  settings.insert("gui/saltLength", integer);
  integer = qAbs(settings.value("kernel/gcryctl_init_secmem",
				65536).toInt(&ok));

  if(!ok)
    integer = 65536;
  else if(integer < 65536 || integer > 999999999)
    integer = 65536;

  settings.insert("kernel/gcryctl_init_secmem", integer);
  integer = qAbs
    (settings.value("kernel/server_account_verification_window_msecs",
		    15000).toInt(&ok));

  if(!ok)
    integer = 15000;
  else if(integer < 1 || integer > 999999999)
    integer = 15000;

  settings.insert
    ("kernel/server_account_verification_window_msecs", integer);

  /*
  ** Correct timer intervals.
  */

  integer = settings.value("gui/emailRetrievalInterval", 5).toInt(&ok);

  if(!ok)
    integer = 5;
  else if(integer < 5 || integer > 60)
    integer = 5;

  settings.insert("gui/emailRetrievalInterval", integer);
  rational = settings.value("gui/poptasticRefreshInterval", 5.00).
    toDouble(&ok);

  if(!ok)
    rational = 5.00;
  else if(rational < 5.00)
    rational = 5.00;

  settings.insert("gui/poptasticRefreshInterval", rational);
  list.clear();
  list << "gui/kernelUpdateTimer"
       << "gui/listenersUpdateTimer"
       << "gui/neighborsUpdateTimer"
       << "gui/participantsUpdateTimer"
       << "gui/starbeamUpdateTimer";

  for(int i = 0; i < list.size(); i++)
    {
      rational = settings.value(list.at(i), 3.50).toDouble(&ok);

      if(!ok)
	rational = 3.50;
      else if(rational < 0.50 || rational > 10.00)
	rational = 3.50;

      settings.insert(list.at(i), rational);
    }
}

QSqlDatabase spoton_misc::database(QString &connectionName)
{
  QSqlDatabase db;
  quint64 dbId = 0;

  QWriteLocker locker(&s_dbMutex);

  dbId = s_dbId += 1;
  locker.unlock();
  db = QSqlDatabase::addDatabase
    ("QSQLITE", QString("spoton_database_%1").arg(dbId));
  connectionName = db.connectionName();
  return db;
}

void spoton_misc::enableLog(const bool state)
{
  QWriteLocker locker(&s_enableLogMutex);

  s_enableLog = state;
}

qint64 spoton_misc::participantCount(const QString &keyType,
				     spoton_crypt *crypt)
{
  if(!crypt)
    return 0;

  QString connectionName("");
  qint64 count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM friends_public_keys "
		      "WHERE key_type_hash = ? AND neighbor_oid = -1");
	query.bindValue
	  (0, crypt->keyedHash(keyType.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count;
}

bool spoton_misc::isValidSignature(const QByteArray &data,
				   const QByteArray &publicKeyHash,
				   const QByteArray &signature,
				   spoton_crypt *crypt)
{
  /*
  ** We must locate the signature public key that's associated with the
  ** provided public key hash. Remember, publicKeyHash is the hash of the
  ** non-signature public key.
  */

  QByteArray publicKey
    (signaturePublicKeyFromPublicKeyHash(publicKeyHash, crypt));

  if(publicKey.isEmpty())
    return false;

  return spoton_crypt::isValidSignature(data, publicKey, signature);
}

bool spoton_misc::isAcceptedIP(const QHostAddress &address,
			       const qint64 id,
			       spoton_crypt *crypt)
{
  if(address.isNull() || address.toString().isEmpty())
    return false;
  else if(!crypt)
    return false;

  QString connectionName("");
  qint64 count = 0;

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
	      count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

bool spoton_misc::authenticateAccount(QByteArray &name,
				      QByteArray &password,
				      const qint64 listenerOid,
				      const QByteArray &hash,
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
	bool exists = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM "
		      "listeners_accounts_consumed_authentications "
		      "WHERE data = ? AND listener_oid = ?");
	query.bindValue(0, hash.toBase64());
	query.bindValue(1, listenerOid);

	if(query.exec())
	  if(query.next())
	    exists = query.value(0).toLongLong() > 0;

	if(!exists)
	  {
	    QByteArray newHash;
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

		  name = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).toByteArray()),
		     &ok);

		  if(ok)
		    password = crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).toByteArray()),
		       &ok);

		  if(ok)
		    newHash = spoton_crypt::keyedHash
		      (QDateTime::currentDateTime().toUTC().
		       toString("MMddyyyyhhmm").
		       toLatin1() + salt, name + password, "sha512", &ok);

		  if(ok)
		    if(!hash.isEmpty() && !newHash.isEmpty() &&
		       spoton_crypt::memcmp(hash, newHash))
		      {
			found = true;
			break;
		      }

		  if(ok)
		    newHash = spoton_crypt::keyedHash
		      (QDateTime::currentDateTime().toUTC().addSecs(60).
		       toString("MMddyyyyhhmm").
		       toLatin1() + salt, name + password, "sha512", &ok);

		  if(ok)
		    if(!hash.isEmpty() && !newHash.isEmpty() &&
		       spoton_crypt::memcmp(hash, newHash))
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

		query.exec("PRAGMA secure_delete = ON");
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
		    query.bindValue(0, hash.toBase64());
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
  qint64 count = -1;

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
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count == 0;
}

bool spoton_misc::isValidBuzzMagnetData(const QByteArray &data)
{
  QList<QByteArray> list(data.split('\n'));
  bool valid = false;

  for(int i = 0; i < 7; i++)
    {
      QByteArray str(QByteArray::fromBase64(list.value(i)));

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
	  bool ok = true;
	  int integer = str.toInt(&ok);

	  if(integer < 10000 || integer > 999999999 || !ok)
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

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

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

	  bool ok = true;
	  int integer = str.toInt(&ok);

	  if(integer < 10000 || integer > 999999999 || !ok)
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

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

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

bool spoton_misc::isValidStarBeamMissingLinksMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str.startsWith("fn="))
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
      else if(str.startsWith("ps="))
	{
	  str.remove(0, 3);

	  bool ok = true;
	  qint64 integer = str.toLongLong(&ok);

	  if(integer < 1024 || !ok) // Please see controlcenter.ui.
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
      else if(str.startsWith("ml="))
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

	  if(str != "urn:starbeam-missing-links")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    tokens += 1;
	}
    }

  if(tokens == 4)
    valid = true;

 done_label:
  return valid;
}

void spoton_misc::prepareSignalHandler(void (*sig_handler) (int))
{
  QList<int> list;
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
  struct sigaction act;
#endif
  list << SIGABRT
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
       << SIGBUS
#endif
       << SIGFPE
       << SIGILL
       << SIGINT
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
       << SIGQUIT
#endif
       << SIGSEGV
       << SIGTERM;

  while(!list.isEmpty())
    {
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
      act.sa_handler = sig_handler;
      sigemptyset(&act.sa_mask);
      act.sa_flags = 0;
      sigaction(list.takeFirst(), &act, 0);
#else
      signal(list.takeFirst(), sig_handler);
#endif
    }
}

void spoton_misc::vacuumAllDatabases(void)
{
  QStringList list;

  list << "buzz_channels.db"
       << "email.db"
       << "friends_public_keys.db"
       << "idiotes.db"
       << "kernel.db"
       << "listeners.db"
       << "neighbors.db"
       << "shared.db"
       << "starbeam.db";

  while(!list.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = database(connectionName);

	db.setDatabaseName(homePath() + QDir::separator() + list.takeFirst());

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.exec("VACUUM");
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

QByteArray spoton_misc::findPublicKeyHashGivenHash
(const QByteArray &randomBytes,
 const QByteArray &hash, const QByteArray &hashKey,
 const QByteArray &hashType, spoton_crypt *crypt)
{
  /*
  ** Locate the public key's hash of the public key whose
  ** hash is identical to the provided hash.
  */

  if(!crypt)
    return QByteArray();

  QByteArray publicKeyHash;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT public_key, public_key_hash FROM "
		      "friends_public_keys WHERE "
		      "neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray publicKey;
	      bool ok = true;

	      publicKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		{
		  QByteArray computedHash;

		  computedHash = spoton_crypt::keyedHash
		    (randomBytes + publicKey, hashKey, hashType, &ok);

		  if(ok)
		    if(!computedHash.isEmpty() && !hash.isEmpty() &&
		       spoton_crypt::memcmp(computedHash, hash))
		      {
			publicKeyHash = QByteArray::fromBase64
			  (query.value(1).toByteArray());
			break;
		      }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKeyHash;
}

bool spoton_misc::isValidInstitutionMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str.startsWith("in="))
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
      else if(str.startsWith("ct="))
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
      else if(str.startsWith("pa="))
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
      else if(str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:institution")
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

bool spoton_misc::isIpBlocked(const QHostAddress &address,
			      spoton_crypt *crypt)
{
  if(address.isNull() || address.toString().isEmpty())
    return true;
  else if(!crypt)
    return true;

  QString connectionName("");
  qint64 count = -1;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM neighbors WHERE "
		      "remote_ip_address_hash = ? AND "
		      "status_control = 'blocked'");
	query.bindValue
	  (0, crypt->
	   keyedHash(address.toString().toLatin1(), &ok).toBase64());

	if(ok)
	  if(query.exec())
	    if(query.next())
	      count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

QPair<QByteArray, QByteArray> spoton_misc::decryptedAdaptiveEchoPair
(const QPair<QByteArray, QByteArray> pair, spoton_crypt *crypt)
{
  if(!crypt)
    return QPair<QByteArray, QByteArray> ();

  QByteArray t1(pair.first);
  QByteArray t2(pair.second);
  bool ok = true;

  t1 = crypt->decryptedAfterAuthenticated(t1, &ok);

  if(ok)
    t2 = crypt->decryptedAfterAuthenticated(t2, &ok);

  if(ok)
    return QPair<QByteArray, QByteArray> (t1, t2);
  else
    return QPair<QByteArray, QByteArray> ();
}

QHostAddress spoton_misc::peerAddressAndPort(const int socketDescriptor,
					     quint16 *port)
{
  QHostAddress address;
  socklen_t length = 0;
#ifdef Q_OS_OS2
  struct sockaddr peeraddr;
#else
  struct sockaddr_storage peeraddr;
#endif

  length = sizeof(peeraddr);

  if(port)
    *port = 0;

  if(getpeername(socketDescriptor, (struct sockaddr *) &peeraddr,
		 &length) == 0)
    {
#ifndef Q_OS_OS2
      if(peeraddr.ss_family == AF_INET)
#endif
	{
	  spoton_type_punning_sockaddr_t *sockaddr =
	    (spoton_type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      address.setAddress
		(ntohl(sockaddr->sockaddr_in.sin_addr.s_addr));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in.sin_port);
	    }
	}
#ifndef Q_OS_OS2
      else
	{
	  spoton_type_punning_sockaddr_t *sockaddr =
	    (spoton_type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      Q_IPV6ADDR temp;

	      memcpy(&temp.c, &sockaddr->sockaddr_in6.sin6_addr.s6_addr,
		     sizeof(temp.c));
	      address.setAddress(temp);
	      address.setScopeId
		(QString::number(sockaddr->sockaddr_in6.sin6_scope_id));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in6.sin6_port);
	    }
	}
#endif
    }

  return address;
}

bool spoton_misc::saveGemini(const QPair<QByteArray, QByteArray> &gemini,
			     const QString &oid,
			     spoton_crypt *crypt)
{
  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ? WHERE OID = ? AND "
		      "neighbor_oid = -1");

	if(gemini.first.isEmpty() || gemini.second.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    if(crypt)
	      {
		query.bindValue
		  (0, crypt->encryptedThenHashed(gemini.first,
						 &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, crypt->encryptedThenHashed(gemini.second,
						   &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
	      }
	  }

	query.bindValue(2, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

QHash<QString, QVariant> spoton_misc::poptasticSettings(spoton_crypt *crypt,
							bool *ok)
{
  if(!crypt)
    return QHash<QString, QVariant> ();

  QHash<QString, QVariant> hash;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT * FROM poptastic") && query.next())
	  {
	    QSqlRecord record(query.record());

	    for(int i = 0; i < record.count(); i++)
	      {
		if(record.fieldName(i) == "proxy_enabled" ||
		   record.fieldName(i) == "proxy_password" ||
		   record.fieldName(i) == "proxy_server_address" ||
		   record.fieldName(i) == "proxy_server_port" ||
		   record.fieldName(i) == "proxy_username" ||
		   record.fieldName(i).endsWith("_password") ||
		   record.fieldName(i).endsWith("_server_address") ||
		   record.fieldName(i).endsWith("_server_port") ||
		   record.fieldName(i).endsWith("_username"))
		  {
		    QByteArray bytes
		      (QByteArray::fromBase64(record.value(i).
					      toByteArray()));
		    bool ok = true;

		    bytes = crypt->decryptedAfterAuthenticated(bytes, &ok);

		    if(ok)
		      hash.insert(record.fieldName(i), bytes);
		    else
		      break;
		  }
		else
		  hash.insert(record.fieldName(i), record.value(i));
	      }

	    if(hash.size() != record.count())
	      if(ok)
		*ok = false;
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return hash;
}

void spoton_misc::saveParticipantStatus(const QByteArray &name,
					const QByteArray &publicKeyHash,
					const QByteArray &status,
					const QByteArray &timestamp,
					const int seconds,
					spoton_crypt *crypt)
{
  QDateTime dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      logError
	("spoton_misc(): saveParticipantStatus(): "
	 "invalid date-time object.");
      return;
    }

  QDateTime now(QDateTime::currentDateTimeUtc());

  dateTime.setTimeSpec(Qt::UTC);
  now.setTimeSpec(Qt::UTC);

  int secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= seconds))
    {
      logError
	(QString("spoton_misc::saveParticipantStatus(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	if(status.isEmpty())
	  {
	    if(name.isEmpty())
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(1, publicKeyHash.toBase64());
	      }
	    else if(crypt)
	      {
		bool ok = true;

		query.prepare("UPDATE friends_public_keys SET "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(1, publicKeyHash.toBase64());
		query.exec();
		query.prepare("UPDATE friends_public_keys SET "
			      "name = ? "
			      "WHERE name_changed_by_user = 0 AND "
			      "neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0,
		   crypt->
		   encryptedThenHashed(name.
				       mid(0, spoton_common::
					   NAME_MAXIMUM_LENGTH), &ok).
		   toBase64());
		query.bindValue(1, publicKeyHash.toBase64());

		if(ok)
		  query.exec();
	      }
	  }
	else
	  {
	    if(name.isEmpty())
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");

		if(status == "away" || status == "busy" ||
		   status == "offline" || status == "online")
		  query.bindValue(0, status);
		else
		  query.bindValue(0, "offline");

		query.bindValue
		  (1, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(2, publicKeyHash.toBase64());
	      }
	    else if(crypt)
	      {
		QDateTime now(QDateTime::currentDateTime());
		bool ok = true;

		query.prepare("UPDATE friends_public_keys SET "
			      "name = ?, "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE name_changed_by_user = 0 AND "
			      "neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0,
		   crypt->
		   encryptedThenHashed(name.
				       mid(0, spoton_common::
					   NAME_MAXIMUM_LENGTH), &ok).
		   toBase64());

		if(status == "away" || status == "busy" ||
		   status == "offline" || status == "online")
		  query.bindValue(1, status);
		else
		  query.bindValue(1, "offline");

		query.bindValue
		  (2, now.toString(Qt::ISODate));
		query.bindValue(3, publicKeyHash.toBase64());

		if(ok)
		  query.exec();

		query.prepare("UPDATE friends_public_keys SET "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");

		if(status == "away" || status == "busy" ||
		   status == "offline" || status == "online")
		  query.bindValue(0, status);
		else
		  query.bindValue(0, "offline");

		query.bindValue
		  (1, now.toString(Qt::ISODate));
		query.bindValue(2, publicKeyHash.toBase64());
		query.exec();
	      }
	  }

	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

bool spoton_misc::prepareUrlDistillersDatabase(void)
{
  QString connectionName("");
  bool ok = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!query.exec("CREATE TABLE IF NOT EXISTS distillers ("
		       "direction TEXT NOT NULL DEFAULT 'download', "
		       "domain TEXT NOT NULL, "
		       "domain_hash TEXT PRIMARY KEY NOT NULL)"))
	  ok = false;
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

bool spoton_misc::prepareUrlKeysDatabase(void)
{
  QString connectionName("");
  bool ok = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!query.exec("CREATE TABLE IF NOT EXISTS import_key_information ("
		       "cipher_type TEXT NOT NULL, "
		       "symmetric_key TEXT NOT NULL)"))
	  ok = false;

	if(!query.exec("CREATE TRIGGER IF NOT EXISTS "
		       "import_key_information_trigger "
		       "BEFORE INSERT ON import_key_information "
		       "BEGIN "
		       "DELETE FROM import_key_information; "
		       "END"))
	  ok = false;

	if(!query.exec("CREATE TABLE IF NOT EXISTS remote_key_information ("
		       "cipher_type TEXT NOT NULL, "
		       "encryption_key TEXT NOT NULL, "
		       "hash_key TEXT NOT NULL, "
		       "hash_type TEXT NOT NULL)"))
	  ok = false;

	if(!query.exec("CREATE TRIGGER IF NOT EXISTS "
		       "remote_key_information_trigger "
		       "BEFORE INSERT ON remote_key_information "
		       "BEGIN "
		       "DELETE FROM remote_key_information; "
		       "END"))
	  ok = false;
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

int spoton_misc::user_interfaces(void)
{
  QString connectionName("");
  int count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("SELECT statistic, value FROM kernel_statistics "
		      "ORDER BY statistic"))
	  while(query.next())
	    if(query.value(0).toString().toLower().
	       contains("user interfaces"))
	      {
		count = query.value(1).toInt();
		break;
	      }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count;
}
