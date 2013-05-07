/*
** Copyright (c) 2012, 2013 Alexis Megas
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
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QString>
#include <QtDebug>

#include <limits>

#include "spot-on-gcrypt.h"
#include "spot-on-misc.h"
#include "spot-on-send.h"

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
extern "C"
{
#include <GeoIP.h>
}
#endif

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
  QSqlDatabase::removeDatabase("spoton_misc");
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS country_inclusion ("
		   "country BLOB NOT NULL, "
		   "accepted BLOB NOT NULL, "
		   "hash TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS friends_public_keys ("
		   "name TEXT NOT NULL DEFAULT 'unknown', "
		   "public_key TEXT NOT NULL, "
		   "public_key_hash TEXT PRIMARY KEY NOT NULL, "
		   /*
		   ** Why do we need the neighbor's OID?
		   ** When a neighbor shares a public key, we need
		   ** to be able to remove the key if the socket connection
		   ** is lost before we accept the friendship. The field
		   ** provides us with some safety.
		   */
		   "neighbor_oid INTEGER DEFAULT -1, "
		   "status TEXT NOT NULL DEFAULT 'offline', "
		   "last_status_update TEXT NOT NULL DEFAULT 'now')");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

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

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

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
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS listeners ("
		   "ip_address TEXT NOT NULL, "
		   "port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'off', "
		   "status_control TEXT NOT NULL DEFAULT 'online', "
		   "connections INTEGER NOT NULL DEFAULT 0, "
		   "maximum_clients INTEGER NOT NULL DEFAULT 5, "
		   "external_ip_address TEXT, "
		   "external_port TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS neighbors ("
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
		   "uuid TEXT, "
		   "country TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL, "
		   "remote_ip_address_hash TEXT NOT NULL, "
		   "qt_country_hash TEXT)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	/*
	** A copy of the shared public key from the idiotes
	** database will be stored in the public_keys database.
	*/

	query.exec("CREATE TABLE IF NOT EXISTS public_keys ("
		   "key TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "urls.db");

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
		   "hash TEXT PRIMARY KEY NOT NULL, "
		   "title BLOB NOT NULL, "
		   "url BLOB NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");
}

void spoton_misc::logError(const QString &error)
{
  QFile file(homePath() + QDir::separator() + "error_log.dat");

  if(file.size() >= 5 * 1024)
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
      file.write(error.toLatin1());
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

#ifdef Q_OS_WIN32
  /*
  ** Windows is awful.
  */

  gi = GeoIP_open("GeoIP\\GeoIP.dat", GEOIP_MEMORY_CACHE);
#else
  gi = GeoIP_open(SPOTON_GEOIP_DATA_FILE, GEOIP_MEMORY_CACHE);
#endif

  if(gi)
    code = GeoIP_country_code_by_addr
      (gi, ipAddress.toLatin1().constData());
  else
    logError("spoton_misc::countryCodeFromIPAddress(): gi is 0.");

  GeoIP_delete(gi);
#else
  Q_UNUSED(ipAddress);
#endif

  if(!code || strlen(code) == 0)
    return QString("Unknown");
  else
    return QString(code);
}

QString spoton_misc::countryNameFromIPAddress(const QString &ipAddress)
{
  const char *country = 0;

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  GeoIP *gi = 0;

#ifdef Q_OS_WIN32
  /*
  ** Windows is awful.
  */

  gi = GeoIP_open("GeoIP\\GeoIP.dat", GEOIP_MEMORY_CACHE);
#else
  gi = GeoIP_open
    (SPOTON_GEOIP_DATA_FILE, GEOIP_MEMORY_CACHE);
#endif

  if(gi)
    country = GeoIP_country_name_by_addr
      (gi, ipAddress.toLatin1().constData());
  else
    logError("spoton_misc::countryNameFromIPAddress(): gi is 0.");

  GeoIP_delete(gi);
#else
  Q_UNUSED(ipAddress);
#endif

  if(!country || strlen(country) == 0)
    return QString("Unknown");
  else
    return QString(country);
}

void spoton_misc::populateCountryDatabase(spoton_gcrypt *crypt)
{
  if(!crypt)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QList<QLocale> allLocales
	  (QLocale::matchingLocales(QLocale::AnyLanguage, QLocale::AnyScript,
				    QLocale::AnyCountry));

	while(!allLocales.isEmpty())
	  {
	    QLocale locale(allLocales.takeFirst());
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO country_inclusion "
			  "(country, accepted, hash) "
			  "VALUES (?, ?, ?)");
	    query.bindValue
	      (0, crypt->encrypted(QLocale::countryToString(locale.country()).
				   toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->encrypted(QString::number(1).toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(2,
		 crypt->keyedHash(QLocale::countryToString(locale.country()).
				  toLatin1(), &ok).toBase64());

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");
}

bool spoton_misc::countryAllowedToConnect(const QString &country,
					  spoton_gcrypt *crypt)
{
  if(!crypt)
    return false;

  bool allowed = false;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT accepted FROM country_inclusion WHERE "
		      "hash = ?");
	query.bindValue(0, crypt->keyedHash(country.toLatin1(), &ok).
			toBase64());

	if(ok)
	  if(query.exec())
	    if(query.next())
	      allowed = crypt->decrypted(QByteArray::
					 fromBase64(query.
						    value(0).
						    toByteArray()),
					 &ok).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");
  return allowed;
}

void spoton_misc::populateUrlsDatabase(const QList<QList<QVariant> > &list,
				       spoton_gcrypt *crypt)
{
  if(!crypt)
    return;

  prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "urls.db");

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

  QSqlDatabase::removeDatabase("spoton_misc");
}

bool spoton_misc::saveFriendshipBundle(const QByteArray &name,
				       const QByteArray &publicKey,
				       const int neighborOid,
				       QSqlDatabase &db)
{
  if(!db.isOpen())
    return false;

  QSqlQuery query(db);
  bool ok = true;

  query.prepare("INSERT OR REPLACE INTO friends_public_keys "
		"(name, public_key, public_key_hash, neighbor_oid) "
		"VALUES (?, ?, ?, ?)");
  query.bindValue(0, name);
  query.bindValue(1, publicKey);
  query.bindValue
    (2, spoton_gcrypt::sha512Hash(publicKey, &ok).toBase64());
  query.bindValue(3, neighborOid);

  if(ok)
    ok = query.exec();

  return ok;
}

void spoton_misc::retrieveSymmetricData(QByteArray &publicKey,
					QByteArray &symmetricKey,
					QByteArray &symmetricKeyAlgorithm,
					QString &neighborOid,
					const QString &oid)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT neighbor_oid, public_key "
			      "FROM friends_public_keys WHERE "
			      "OID = %1").arg(oid)))
	  if(query.next())
	    {
	      QByteArray cipherType(spoton_gcrypt::randomCipherType());
	      int algorithm = gcry_cipher_map_name(cipherType.constData());
	      size_t symmetricKeyLength =
		gcry_cipher_get_algo_keylen(algorithm);

	      if(symmetricKeyLength > 0)
		{
		  neighborOid = query.value(0).toString();
		  publicKey = query.value(1).toByteArray();
		  symmetricKey.resize(symmetricKeyLength);
		  gcry_randomize
		    (static_cast<void *> (symmetricKey.data()),
		     static_cast<size_t> (symmetricKey.length()),
		     GCRY_STRONG_RANDOM);
		  symmetricKeyAlgorithm = cipherType;
		}
	      else
		logError
		  ("spoton_misc::retrieveSymmetricData(): "
		   "gcry_cipher_get_algo_keylen() failure.");
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_misc");
}

bool spoton_misc::isAcceptedParticipant(const QByteArray &publicKeyHash)
{
  int count = 0;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_misc");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    count = query.value(0).toInt();
      }
  }

  QSqlDatabase::removeDatabase("spoton_misc");
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
	(QHostAddress::parseSubnet("fc00::/7"));
      QPair<QHostAddress, int> pair2
	(QHostAddress::parseSubnet("fe80::/10"));

      isPrivate = address.isInSubnet(pair1) || address.isInSubnet(pair2);
    }

  return isPrivate;
}
