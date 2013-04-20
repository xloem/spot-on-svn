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

#ifndef _spoton_misc_h_
#define _spoton_misc_h_

#include <QSqlDatabase>
#include <QString>
#include <QVariant>

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
extern "C"
{
#include <GeoIP.h>
}
#endif

class spoton_gcrypt;

class spoton_misc
{
 public:
  static QString countryCodeFromIPAddress(const QString &ipAddress);
  static QString countryNameFromIPAddress(const QString &ipAddress);
  static QString homePath(void);
  static bool countryAllowedToConnect(const QString &country,
				      spoton_gcrypt *crypt);
  static bool isGnome(void);
  static bool saveSymmetricBundle(const QByteArray &name,
				  const QByteArray &publicKey,
				  const QByteArray &symmetricKey,
				  const QByteArray &symmetricKeyAlgorithm,
				  const int neighborOid,
				  QSqlDatabase &db,
				  spoton_gcrypt *crypt);
  static void logError(const QString &error);
  static void populateCountryDatabase(spoton_gcrypt *crypt);
  static void populateUrlsDatabase(const QList<QList<QVariant> > &list,
				   spoton_gcrypt *gcrypt);
  static void prepareDatabases(void);
  static void retrieveSymmetricData(QByteArray &publicKey,
				    QByteArray &symmetricKey,
				    QByteArray &symmetricKeyAlgorithm,
				    QString &neighborOid,
				    const QString &oid,
				    spoton_gcrypt *crypt);

 private:
#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  GeoIP *s_gi;
#endif
  spoton_misc(void);
};

#endif
