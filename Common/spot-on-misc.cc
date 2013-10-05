/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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

bool spoton_misc::s_enableLog = false;
qint64 spoton_misc::s_dbId = 0;

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

    db.setDatabaseName(homePath() + QDir::separator() +
		       "accepted_ips.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS accepted_ips ("
		   "ip_address TEXT NOT NULL, "
		   "ip_address_hash TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS country_inclusion ("
		   "country TEXT NOT NULL, "
		   "accepted TEXT NOT NULL, "
		   "country_hash TEXT PRIMARY KEY NOT NULL)");
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
					  ** Hash of the message and
					  ** the subject.
					  */
		   "message BLOB NOT NULL, "
		   "message_code TEXT NOT NULL, " /*
						  ** Not used.
						  */
		   "participant_oid TEXT NOT NULL, "
		   "receiver_sender TEXT NOT NULL, "
		   "receiver_sender_hash TEXT NOT NULL, " /*
							  ** Sha-512 hash of
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
		   "message_bundle_hash TEXT NOT NULL, "
		   "recipient_hash TEXT NOT NULL, " /*
						    ** Sha-512 hash of the
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
							 ** Sha-512
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
	   "last_status_update TEXT NOT NULL DEFAULT 'now')");
	query.exec
	  ("CREATE TABLE IF NOT EXISTS relationships_with_signatures ("
	   "public_key_hash TEXT PRIMARY KEY NOT NULL, " /*
							 ** Sha-512
							 ** hash of
							 ** the public
							 ** key.
							 */
	   "signature_public_key_hash "
	   "TEXT NOT NULL)"); /*
			      ** Sha-512 hash of the signature
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

	query.exec("CREATE TABLE IF NOT EXISTS listeners ("
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
						      ** The hash of the
						      ** IP address,
						      ** the port, and
						      ** the scope.
						      */
		   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
		   "echo_mode TEXT NOT NULL, "
		   "certificate BLOB NOT NULL, "
		   "private_key BLOB NOT NULL, "
		   "public_key BLOB NOT NULL, "       // Not used.
		   "use_accounts INTEGER NOT NULL DEFAULT 0)");
	query.exec("CREATE TABLE IF NOT EXISTS listeners_accounts ("
		   "account_name TEXT NOT NULL, "
		   "account_name_hash TEXT NOT NULL, "
		   "account_password TEXT NOT NULL, "
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (listener_oid, account_name_hash), "
		   "FOREIGN KEY (listener_oid) REFERENCES "
		   "listeners (OID))");
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
	  ("CREATE TABLE IF NOT EXISTS neighbors ("
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
					      ** Hash of the proxy IP address,
					      ** the proxy port, the remote IP
					      ** address, the remote
					      ** port, and the scope id.
					      */
	   "remote_ip_address_hash TEXT NOT NULL, "
	   "qt_country_hash TEXT, "
	   "user_defined INTEGER NOT NULL DEFAULT 1, "
	   "proxy_hostname TEXT NOT NULL, "
	   "proxy_password TEXT NOT NULL, "
	   "proxy_port TEXT NOT NULL, "
	   "proxy_type TEXT NOT NULL, "
	   "proxy_username TEXT NOT NULL, "
	   "is_encrypted INTEGER NOT NULL DEFAULT 0, "
	   "maximum_buffer_size INTEGER NOT NULL DEFAULT 131072, "
	   "maximum_content_length INTEGER NOT NULL DEFAULT 65536, "
	   "echo_mode TEXT NOT NULL, "
	   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
	   "uptime INTEGER NOT NULL DEFAULT 0, "
	   "peer_certificate BLOB NOT NULL, "
	   "allow_exceptions INTEGER NOT NULL DEFAULT 0, "
	   "bytes_read INTEGER NOT NULL DEFAULT 0, "
	   "bytes_written INTEGER NOT NULL DEFAULT 0, "
	   "ssl_session_cipher TEXT, "
	   "ssl_required INTEGER NOT NULL DEFAULT 1, "
	   "account_name TEXT NOT NULL, "
	   "account_password TEXT NOT NULL)");
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

  if(file.size() >= 25 * 1000 * 1024)
    /*
    ** Too large!
    */

    file.remove();

  static QString s_lastError("");

  if(error.trimmed() == s_lastError)
    {
      if(!file.size() == 0)
	return;
    }
  else
    s_lastError = error.trimmed();

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
      file.write(s_lastError.toLatin1());
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
  QSettings settings;

  gi = GeoIP_open
    (settings.value("gui/geoipPath", "GeoIP.dat").toByteArray().constData(),
     GEOIP_MEMORY_CACHE);

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
  QSettings settings;

  gi = GeoIP_open
    (settings.value("gui/geoipPath", "GeoIP.dat").toByteArray().constData(),
     GEOIP_MEMORY_CACHE);

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

void spoton_misc::populateCountryDatabase(spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
#if QT_VERSION >= 0x040800
	QList<QLocale> allLocales
	  (QLocale::matchingLocales(QLocale::AnyLanguage, QLocale::AnyScript,
				    QLocale::AnyCountry));
#else
	QStringList allLocales;

	allLocales << "Afghanistan"
		   << "Albania"
		   << "Algeria"
		   << "AmericanSamoa"
		   << "Angola"
		   << "Argentina"
		   << "Armenia"
		   << "Aruba"
		   << "Australia"
		   << "Austria"
		   << "Azerbaijan"
		   << "Bahrain"
		   << "Bangladesh"
		   << "Barbados"
		   << "Belarus"
		   << "Belgium"
		   << "Belize"
		   << "Benin"
		   << "Bermuda"
		   << "Bhutan"
		   << "Bolivia"
		   << "BosniaAndHerzegowina"
		   << "Botswana"
		   << "Brazil"
		   << "BruneiDarussalam"
		   << "Bulgaria"
		   << "BurkinaFaso"
		   << "Burundi"
		   << "Cambodia"
		   << "Cameroon"
		   << "Canada"
		   << "CapeVerde"
		   << "CentralAfricanRepublic"
		   << "Chad"
		   << "Chile"
		   << "China"
		   << "Colombia"
		   << "Comoros"
		   << "CostaRica"
		   << "Croatia"
		   << "Cyprus"
		   << "CzechRepublic"
		   << "Default"
		   << "DemocraticRepublicOfCongo"
		   << "Denmark"
		   << "Djibouti"
		   << "DominicanRepublic"
		   << "Ecuador"
		   << "Egypt"
		   << "ElSalvador"
		   << "EquatorialGuinea"
		   << "Eritrea"
		   << "Estonia"
		   << "Ethiopia"
		   << "FaroeIslands"
		   << "Finland"
		   << "France"
		   << "FrenchGuiana"
		   << "Gabon"
		   << "Georgia"
		   << "Germany"
		   << "Ghana"
		   << "Greece"
		   << "Greenland"
		   << "Guadeloupe"
		   << "Guam"
		   << "Guatemala"
		   << "Guinea"
		   << "GuineaBissau"
		   << "Guyana"
		   << "Honduras"
		   << "HongKong"
		   << "Hungary"
		   << "Iceland"
		   << "India"
		   << "Indonesia"
		   << "Iran"
		   << "Iraq"
		   << "Ireland"
		   << "Israel"
		   << "Italy"
		   << "IvoryCoast"
		   << "Jamaica"
		   << "Japan"
		   << "Jordan"
		   << "Kazakhstan"
		   << "Kenya"
		   << "Kuwait"
		   << "Kyrgyzstan"
		   << "Lao"
		   << "LatinAmericaAndTheCaribbean"
		   << "Latvia"
		   << "Lebanon"
		   << "Lesotho"
		   << "Liberia"
		   << "LibyanArabJamahiriya"
		   << "Liechtenstein"
		   << "Lithuania"
		   << "Luxembourg"
		   << "Macau"
		   << "Macedonia"
		   << "Madagascar"
		   << "Malaysia"
		   << "Mali"
		   << "Malta"
		   << "MarshallIslands"
		   << "Martinique"
		   << "Mauritius"
		   << "Mayotte"
		   << "Mexico"
		   << "Moldova"
		   << "Monaco"
		   << "Mongolia"
		   << "Montenegro"
		   << "Morocco"
		   << "Mozambique"
		   << "Myanmar"
		   << "Namibia"
		   << "Nepal"
		   << "Netherlands"
		   << "NewZealand"
		   << "Nicaragua"
		   << "Niger"
		   << "Nigeria"
		   << "NorthernMarianaIslands"
		   << "Norway"
		   << "Oman"
		   << "Pakistan"
		   << "Panama"
		   << "Paraguay"
		   << "PeoplesRepublicOfCongo"
		   << "Peru"
		   << "Philippines"
		   << "Poland"
		   << "Portugal"
		   << "PuertoRico"
		   << "Qatar"
		   << "RepublicOfKorea"
		   << "Reunion"
		   << "Romania"
		   << "RussianFederation"
		   << "Rwanda"
		   << "Saint Barthelemy"
		   << "Saint Martin"
		   << "SaoTomeAndPrincipe"
		   << "SaudiArabia"
		   << "Senegal"
		   << "Serbia"
		   << "SerbiaAndMontenegro"
		   << "Singapore"
		   << "Slovakia"
		   << "Slovenia"
		   << "Somalia"
		   << "SouthAfrica"
		   << "Spain"
		   << "SriLanka"
		   << "Sudan"
		   << "Swaziland"
		   << "Sweden"
		   << "Switzerland"
		   << "SyrianArabRepublic"
		   << "Taiwan"
		   << "Tajikistan"
		   << "Tanzania"
		   << "Thailand"
		   << "Togo"
		   << "Tonga"
		   << "TrinidadAndTobago"
		   << "Tunisia"
		   << "Turkey"
		   << "USVirginIslands"
		   << "Uganda"
		   << "Ukraine"
		   << "UnitedArabEmirates"
		   << "UnitedKingdom"
		   << "UnitedStates"
		   << "UnitedStatesMinorOutlyingIslands"
		   << "Uruguay"
		   << "Uzbekistan"
		   << "Venezuela"
		   << "VietNam"
		   << "Yemen"
		   << "Yugoslavia"
		   << "Zambia"
		   << "Zimbabwe";
#endif

	while(!allLocales.isEmpty())
	  {
#if QT_VERSION >= 0x040800
	    QLocale locale(allLocales.takeFirst());
	    QString country(QLocale::countryToString(locale.country()));
#else
	    QString country(allLocales.takeFirst());
#endif
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO country_inclusion "
			  "(country, accepted, country_hash) "
			  "VALUES (?, ?, ?)");

	    if(!country.isEmpty())
	      query.bindValue
		(0, crypt->encrypted(country.toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->encrypted(QString::number(1).toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(2,
		 crypt->keyedHash(country.toLatin1(), &ok).toBase64());

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

bool spoton_misc::countryAllowedToConnect(const QString &country,
					  spoton_crypt *crypt)
{
  if(!crypt)
    return false;

  QString connectionName("");
  bool allowed = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT accepted FROM country_inclusion WHERE "
		      "country_hash = ?");
	query.bindValue(0, crypt->keyedHash(country.toLatin1(), &ok).
			toBase64());

	if(ok)
	  if(query.exec())
	    if(query.next())
	      {
		allowed = crypt->decrypted(QByteArray::
					   fromBase64(query.
						      value(0).
						      toByteArray()),
					   &ok).toInt(); /*
							 ** toInt() failure
							 ** returns zero.
							 */

		if(!ok)
		  allowed = false;
	      }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return allowed;
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
		"(gemini, key_type, name, public_key, public_key_hash, "
		"neighbor_oid, last_status_update) "
		"VALUES ((SELECT gemini FROM friends_public_keys WHERE "
		"public_key_hash = ?), ?, ?, ?, ?, ?, ?)");
  query.bindValue(0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());
  query.bindValue(1, keyType.constData());

  if(keyType == "chat" || keyType == "email" || keyType == "url")
    {
      if(name.isEmpty())
	query.bindValue(2, "unknown");
      else
	query.bindValue
	  (2, name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
    }
  else // Signature keys will be labeled as their type.
    query.bindValue(2, keyType);

  query.bindValue(3, publicKey);
  query.bindValue
    (4, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());
  query.bindValue(5, neighborOid);
  query.bindValue
    (6, QDateTime::currentDateTime().toString(Qt::ISODate));

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

void spoton_misc::retrieveSymmetricData(QByteArray &gemini,
					QByteArray &publicKey,
					QByteArray &symmetricKey,
					QString &neighborOid,
					const QByteArray &cipherType,
					const QString &oid,
					spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT gemini, neighbor_oid, public_key "
			      "FROM friends_public_keys WHERE "
			      "OID = %1").arg(oid)))
	  if(query.next())
	    {
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(cipherType);

	      if(symmetricKeyLength > 0)
		{
		  bool ok = true;

		  if(!query.isNull(0))
		    gemini = crypt->decrypted
		      (QByteArray::fromBase64(query.
					      value(0).
					      toByteArray()),
		       &ok);

		  neighborOid = query.value(1).toString();
		  publicKey = query.value(2).toByteArray();
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		logError
		  ("spoton_misc::retrieveSymmetricData(): "
		   "cipherKeyLength() failure.");
	    }
      }

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

QByteArray spoton_misc::findGeminiInCosmos(const QByteArray &data,
					   spoton_crypt *crypt)
{
  QByteArray gemini;
  QString connectionName("");

  if(crypt)
    {
      {
	QSqlDatabase db = database(connectionName);

	db.setDatabaseName(homePath() + QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);

	    if(query.exec("SELECT gemini FROM friends_public_keys WHERE "
			  "gemini IS NOT NULL AND key_type = 'chat'"))
	      while(query.next())
		{
		  bool ok = true;

		  gemini = crypt->decrypted
		    (QByteArray::fromBase64(query.
					    value(0).
					    toByteArray()),
		     &ok);

		  if(ok)
		    if(!gemini.isEmpty())
		      {
			spoton_crypt crypt("aes256",
					   QString("sha512"),
					   QByteArray(),
					   gemini,
					   0,
					   0,
					   QString(""));

			crypt.decrypted(data, &ok);

			if(ok)
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

	query.exec("UPDATE neighbors SET external_ip_address = NULL, "
		   "is_encrypted = 0, "
		   "local_ip_address = NULL, local_port = NULL, "
		   "ssl_session_cipher = NULL, "
		   "status = 'disconnected', uptime = 0");
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

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

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
					const QString &statusControl,
					spoton_crypt *crypt)
{
  if(!crypt)
    return;

  if(address.isNull())
    return;

  if(!(statusControl == "connected" || statusControl == "disconnected"))
    return;

  QString connectionName("");

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
		   "peer_certificate, "
		   "account_name, "
		   "account_password) "
		   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
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
	     encrypted(QString::number(port).toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5,
	     crypt->encrypted(address.scopeId().toLatin1(),
			      &ok).toBase64());

	query.bindValue(6, statusControl);

	if(ok)
	  query.bindValue
	    (7,
	     crypt->keyedHash((address.toString() +
			       QString::number(port) +
			       address.scopeId()).toLatin1(), &ok).
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
	     encrypted(QByteArray("{00000000-0000-0000-0000-000000000000}"),
		       &ok).toBase64());

	if(ok)
	  query.bindValue
	    (19, crypt->encrypted(QByteArray("full"), &ok).
	     toBase64());

	if(ok)
	  {
	    QSettings settings;
	    QString error("");
	    int keySize = 2048;

	    keySize = settings.value
	      ("gui/publishedKeySize", "2048").toInt(&ok);

	    if(!ok)
	      keySize = 2048;
	    else if(!(keySize == 2048 || keySize == 3072 || keySize == 4096))
	      keySize = 2048;

	    query.bindValue(20, keySize);
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

  settings["gui/congestionCost"] = integer;
  str = settings.value("gui/iconSet", "nouve").toString().trimmed();

  if(!(str == "nouve" || str == "nuvola"))
    str = "nouve";

  settings["gui/iconSet"] = str;
  integer = qAbs(settings.value("gui/iterationCount", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;

  settings["gui/iterationCount"] = integer;
  str = settings.value("gui/kernelCipherType").toString().trimmed();

  if(!(str == "aes256" || str == "camellia256" ||
       str == "randomized" ||
       str == "serpent256" || str == "twofish"))
    str = "aes256";

  settings["gui/kernelCipherType"] = str;
  integer = qAbs(settings.value("gui/kernelKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 2048 || integer == 3072 || integer == 4096))
    integer = 2048;

  settings["gui/kernelKeySize"] = integer;
  integer = qAbs(settings.value("gui/keySize", 3072).toInt(&ok));

  if(!ok)
    integer = 3072;
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096 || integer == 7680 ||
	    integer == 15360))
    integer = 3072;

  settings["gui/keySize"] = integer;
  integer = qAbs(settings.value("gui/publishedKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 2048 || integer == 3072 || integer == 4096))
    integer = 2048;

  settings["gui/publishedKeySize"] = integer;
  integer = qAbs(settings.value("gui/saltLength", 256).toInt(&ok));

  if(!ok)
    integer = 256;
  else if(integer < 256)
    integer = 256;

  settings["gui/saltLength"] = integer;
  integer = qAbs(settings.value("gui/gcryctl_init_secmem", 65536).toInt(&ok));

  if(!ok)
    integer = 65536;
  else if(integer < 65536)
    integer = 65536;

  settings["gui/gcryctl_init_secmem"] = integer;
  integer = qAbs(settings.value("kernel/gcryctl_init_secmem",
				65536).toInt(&ok));

  if(!ok)
    integer = 65536;
  else if(integer < 65536)
    integer = 65536;

  settings["kernel/gcryctl_init_secmem"] = integer;
}

QSqlDatabase spoton_misc::database(QString &connectionName)
{
  QSqlDatabase db;

  s_dbId += 1;
  db = QSqlDatabase::addDatabase
    ("QSQLITE", QString("spoton_database_%1").arg(s_dbId));
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
		      "WHERE key_type = ?");
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
  ** provided public key hash. Remember publicKeyHash is the hash of the
  ** non-signature public key.
  */

  QByteArray publicKey(signaturePublicKeyFromPublicKeyHash(publicKeyHash));

  if(publicKey.isEmpty())
    return false;

  return spoton_crypt::isValidSignature(data, publicKey, signature);
}

bool spoton_misc::isAcceptedIP(const QHostAddress &address,
			       spoton_crypt *crypt)
{
  QSettings settings;

  if(!settings.value("gui/acceptedIPs", false).toBool())
    return true;

  if(!crypt)
    return false;

  QString connectionName("");
  int count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "accepted_ips.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM accepted_ips "
		      "WHERE ip_address_hash = ?");
	query.bindValue(0, crypt->keyedHash(address.toString().
					    toLatin1(), &ok).
			toBase64());

	if(query.exec())
	  if(query.next())
	    count = query.value(0).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

bool spoton_misc::authenticateAccount(const qint64 listenerOid,
				      const QByteArray &name,
				      const QByteArray &password,
				      spoton_crypt *crypt)
{
  if(!crypt)
    return false;

  QString connectionName("");
  bool found = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT account_password "
		      "FROM listeners_accounts WHERE "
		      "account_name_hash = ? AND listener_oid = ?");
	query.bindValue
	  (0, crypt->keyedHash(name, &ok).toBase64());
	query.bindValue(1, listenerOid);

	if(ok)
	  if(query.exec())
	    if(query.next())
	      {
		QByteArray bytes
		  (crypt->decrypted(QByteArray::fromBase64(query.value(0).
							   toByteArray()),
				    &ok));

		if(ok)
		  if(bytes == password)
		    found = true;
	      }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return found;
}
