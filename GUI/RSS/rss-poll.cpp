
#include "rss-poll.h"

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
#include "deliberate.h"
#include "addfeed.h"
#include "db-manager.h"
#include "networkaccessmanager.h"
#include <QTimer>
#include <QUrl>
#include <QString>
#include <QDebug>

using namespace deliberate;

namespace arado
{
RssPoll::RssPoll (QObject *parent)
  :QObject (parent),
   dbm (0),
   pollTimer (0),
   feeder (0),
   saveNewItems (false)
{
  feeder = new AddRssFeed (this);
  feedList.clear ();
  pollTimer = new QTimer (this);
  connect (pollTimer, SIGNAL (timeout()), this, SLOT(Poll()));
}

void
RssPoll::SetDB (DBManager *db)
{
  dbm = db;
  feeder->SetDB (dbm);
}

void
RssPoll::Start (bool reportNew)
{
  qDebug () << " RssPoll Start";
  saveNewItems = reportNew;
  int period (5*60); // 5 minutes
  period = Settings().value ("rss/pollperiod",period).toInt();
  Settings().setValue ("rss/pollperiod",period);
  Settings().sync ();
  lastPolled = feedList.begin();
  if (dbm) {
    feedList = dbm->GetFeeds();
    lastNick.clear ();
    lastNick = Settings().value ("rss/lastpolled",lastNick).toString();
    lastPolled = feedList.begin();
    while (lastPolled != feedList.end() 
           && lastPolled->Nick() != lastNick) {
      lastPolled++;
    }
    if (lastPolled == feedList.end()) {
      lastPolled = feedList.begin();
    }
    feeder->SetDB (dbm);
  }
  pollTimer->start (period*1000);
  QTimer::singleShot (3*1000, this, SLOT (Poll()));
}

void
RssPoll::Stop ()
{
  pollTimer->stop ();
  Settings().setValue ("rss/lastpolled",lastNick);
  Settings().sync();
}

void
RssPoll::SetSaveNew (bool saveNew)
{
  saveNewItems = saveNew;
}

void
RssPoll::Poll ()
{
  qDebug () << "RssPoll list length " << feedList.count();
  if (feedList.empty ()) {
    return;
  }
  AradoFeedList::iterator nextPoll = lastPolled;
  nextPoll++;
  if (nextPoll == feedList.end()) {
    nextPoll = feedList.begin();
  }
  if (nextPoll == feedList.end()) {  // empty list ?
    return;
  }
  qDebug () << " Poll Feed " << nextPoll->Nick() ;
  feeder->PollFeed (nextPoll->Url().toString(), saveNewItems);
  lastNick = nextPoll->Nick();
  lastPolled = nextPoll;
  Settings().setValue ("rss/lastpolled",lastNick);
  Settings().sync ();
  emit SigPolledRss (lastNick);
}

} // namespace
