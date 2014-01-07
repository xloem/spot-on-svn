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

#ifndef _spoton_starbeam_writer_h_
#define _spoton_starbeam_writer_h_

#include <QHash>
#include <QReadWriteLock>
#include <QThread>
#include <QTimer>

class spoton_starbeam_writer: public QThread
{
  Q_OBJECT

 public:
  spoton_starbeam_writer(QObject *parent);
  ~spoton_starbeam_writer();
  bool isActive(void) const;
  void append(const QByteArray &data);
  void start(void);
  void stop(void);

 private:
  QHash<QByteArray, QByteArray> m_data;
  QList<QHash<QString, QByteArray> > m_magnets;
  QList<QByteArray> m_novas;
  QReadWriteLock m_keyMutex;
  QReadWriteLock m_mutex;
  QTimer m_keyTimer;
  QTimer m_timer;
  void run(void);

 private slots:
  void slotProcessData(void);
  void slotReadKeys(void);
};

#endif
