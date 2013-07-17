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

#ifndef _spoton_send_h_
#define _spoton_send_h_

#include <QByteArray>
#include <QHostAddress>

class spoton_send
{
 public:
  enum spoton_send_method
  {
    ARTIFICIAL_GET = 0,
    NORMAL_POST
  };

  static QByteArray EOM;
  static QByteArray message0000
    (const QByteArray &message,
     const spoton_send_method sendMethod);
  static QByteArray message0001a(const QByteArray &message);
  static QByteArray message0001b(const QByteArray &message);
  static QByteArray message0002(const QByteArray &message);
  static QByteArray message0010(const QByteArray &message);
  static QByteArray message0011(const QByteArray &keyType,
				const QByteArray &name,
				const QByteArray &publicKey,
				const QByteArray &signature,
				const QByteArray &sPublicKey,
				const QByteArray &sSignature);
  static QByteArray message0012(const QByteArray &message);
  static QByteArray message0013(const QByteArray &message);
  static QByteArray message0014(const QByteArray &uuid);
  static QByteArray message0015(void);
  static QByteArray message0030(const QByteArray &message);
  static QByteArray message0030(const QHostAddress &address,
				const quint16 port,
				const char ttl);
  static QByteArray message0040a(const QByteArray &message,
				 const spoton_send_method sendMethod);
  static QByteArray message0040a
    (const QByteArray &name,
     const QByteArray &id,
     const char ttl);
  static QByteArray message0040b(const QByteArray &message,
				 const spoton_send_method sendMethod);
  static QByteArray message0040b
    (const QByteArray &name,
     const QByteArray &id,
     const QByteArray &message,
     const char ttl,
     const spoton_send_method sendMethod);

 private:
  spoton_send(void);
};

#endif
