#ifndef RSS_POLL_H
#define RSS_POLL_H

/****************************************************************
 * This file is distributed under the following license:
 *
 * Copyright (C) 2010, Arado Team
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 *  Boston, MA  02110-1301, USA.
 ****************************************************************/

#include <QObject>
#include "arado-feed.h"
#include "addfeed.h"

class QTimer;

namespace arado
{

class AddRssFeed;
class DBManager;
class NetworkAccessManager;

class RssPoll : public QObject
{
Q_OBJECT

public:
  RssPoll (QObject *parent=0);

  void  SetDB (DBManager *db);
  void  Start (bool reportNew);
  void  Stop ();
  void  SetSaveNew (bool saveNew);

  QString LastPolled ();

private slots:

  void Poll ();

signals:

  void SigPolledRss (QString nick);

private:

  DBManager               *dbm;
  NetworkAccessManager    *nam;
  QTimer                  *pollTimer;
  AddRssFeed              *feeder;
  AradoFeedList            feedList;
  AradoFeedList::iterator  lastPolled;
  QString                  lastNick;
  bool                     saveNewItems;

};

} // namespace

#endif
