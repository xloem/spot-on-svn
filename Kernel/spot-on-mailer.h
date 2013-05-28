/*
** Copyright (c) 2013 Alexis Megas
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

#ifndef _spoton_mailer_h_
#define _spoton_mailer_h_

#include <QObject>
#include <QTimer>

class spoton_mailer: public QObject
{
  Q_OBJECT

 public:
  spoton_mailer(QObject *parent);
  ~spoton_mailer();

 private:
  QList<QByteArray> m_publicKeyHashes;
  QTimer m_retrieveMailTimer;
  QTimer m_timer;

 private slots:
  void slotRetrieveMail(const QByteArray &publicKeyHash);
  void slotRetrieveMailTimeout(void);
  void slotTimeout(void);

 signals:
  void sendMail(const QByteArray &gemini,
		const QByteArray &message,
		const QByteArray &name,
		const QByteArray &publicKey,
		const QByteArray &subject,
		const qint64 mailOid);
  void sendMailFromPostOffice(const QByteArray &message);
};

#endif
