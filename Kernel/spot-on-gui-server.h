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

#ifndef _spoton_gui_server_h_
#define _spoton_gui_server_h_

#include <QTcpServer>
#include <QTimer>

class spoton_gui_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_gui_server(QObject *parent);
  ~spoton_gui_server();

 private:
  QHash<int, QByteArray> m_guiSocketData;
  QTimer m_generalTimer;

 private slots:
  void slotClientConnected(void);
  void slotClientDisconnected(void);
  void slotNewEMailArrived(void);
  void slotReadyRead(void);
  void slotReceivedChatMessage(const QByteArray &message);
  void slotTimeout(void);

 signals:
  void messageReceivedFromUI(const qint64 oid,
			     const QByteArray &name,
			     const QByteArray &message);
  void publicKeyReceivedFromUI(const qint64 oid,
			       const QByteArray &keyType,
			       const QByteArray &name,
			       const QByteArray &publicKey,
			       const QByteArray &signature,
			       const QString &messageType);
  void publicizeAllListenersPlaintext(void);
  void publicizeListenerPlaintext(const qint64 oid);
  void retrieveMail(void);
};

#endif
