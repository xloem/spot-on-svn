/*
** Copyright (c) 2011 - 10^10^10 Alexis Megas
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

#include <QString>

#include "spot-on-send.h"

QByteArray spoton_send::EOM = "\r\n\r\n\r\n";

QByteArray spoton_send::message0000(const QByteArray &message,
				    const spoton_send_method sendMethod)
{
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0000a(const QByteArray &message,
				     const spoton_send_method sendMethod)
{
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0001a(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0001b(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0002a(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0002b(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0010(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0010&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("type=0010&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0011(const QByteArray &keyType,
				    const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &signature,
				    const QByteArray &sPublicKey,
				    const QByteArray &sSignature)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0011&content=%2\r\n"
     "\r\n\r\n");
  content.append(keyType.toBase64());
  content.append("\n");
  content.append(name.toBase64());
  content.append("\n");
  content.append(publicKey.toBase64());
  content.append("\n");
  content.append(signature.toBase64());
  content.append("\n");
  content.append(sPublicKey.toBase64());
  content.append("\n");
  content.append(sSignature.toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.toBase64().length() +
			QString("type=0011&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content.toBase64());
  return results;
}

QByteArray spoton_send::message0012(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0012&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("type=0012&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0013(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0014(const QByteArray &uuid)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0014&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(uuid.toBase64().length() +
			QString("type=0014&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", uuid.toBase64());
  return results;
}

QByteArray spoton_send::message0030(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0030&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("type=0030&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0030(const QHostAddress &address,
				    const quint16 port,
				    const QString &transport,
				    const QString &orientation)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0030&content=%2\r\n"
     "\r\n\r\n");
  content.append(address.toString().toLatin1().toBase64());
  content.append("\n");
  content.append(QByteArray::number(port).toBase64());
  content.append("\n");
  content.append(address.scopeId().toLatin1().toBase64());
  content.append("\n");
  content.append(transport.toLatin1().toBase64());
  content.append("\n");
  content.append(orientation.toLatin1().toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.toBase64().length() +
			QString("type=0030&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content.toBase64());
  return results;
}

QByteArray spoton_send::message0040a(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0040b(const QByteArray &message,
				     const spoton_send_method sendMethod)
{
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0050(const QByteArray &saltedCredentials,
				    const QByteArray &salt)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0050&content=%2\r\n"
     "\r\n\r\n");
  content.append(saltedCredentials.toBase64());
  content.append("\n");
  content.append(salt.toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.toBase64().length() +
			QString("type=0050&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content.toBase64());
  return results;
}

QByteArray spoton_send::message0051(const QByteArray &saltedCredentials,
				    const QByteArray &salt)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0051&content=%2\r\n"
     "\r\n\r\n");
  content.append(saltedCredentials.toBase64());
  content.append("\n");
  content.append(salt.toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.toBase64().length() +
			QString("type=0051&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content.toBase64());
  return results;
}

QByteArray spoton_send::message0052(void)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0052&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(QByteArray("0").toBase64().length() +
			QString("type=0052&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", QByteArray("0").toBase64());
  return results;
}

QByteArray spoton_send::message0060(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.toBase64().length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message.toBase64());
  return results;
}

QByteArray spoton_send::message0065(const QByteArray &magnet)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0065&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(magnet.toBase64().length() +
			QString("type=0065&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", magnet.toBase64());
  return results;
}
