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

#include "spot-on-external-address.h"

#include <QNetworkReply>
#include <QNetworkRequest>

spoton_external_address::spoton_external_address(QObject *parent):
  QNetworkAccessManager(parent)
{
  m_address = QHostAddress();
}

void spoton_external_address::discover(void)
{
  QNetworkReply *reply = 0;
  QNetworkRequest request;

  request.setUrl(QUrl::fromUserInput("http://checkip.dyndns.org"));
  reply = get(request);
  connect(reply,
	  SIGNAL(error(QNetworkReply::NetworkError)),
	  this,
	  SLOT(slotError(QNetworkReply::NetworkError)));
  connect(reply,
	  SIGNAL(finished(void)),
	  this,
	  SLOT(slotFinished(void)));
}

void spoton_external_address::slotFinished(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply)
    {
      QByteArray bytes(reply->readAll());

      bytes.remove(0, bytes.indexOf("Current IP Address:") +
		   qstrlen("Current IP Address:"));
      bytes = bytes.mid(0, bytes.indexOf("<")).trimmed();
      m_address = QHostAddress(bytes.constData());
      emit ipAddressDiscovered(m_address);
      reply->deleteLater();
    }
}

QHostAddress spoton_external_address::address(void) const
{
  return m_address;
}

void spoton_external_address::slotError(QNetworkReply::NetworkError error)
{
  Q_UNUSED(error);

  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply)
    reply->deleteLater();
}
