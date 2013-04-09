
#include "rss-list.h"

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

#include "arado-feed.h"
#include "arado-url.h"
#include "addfeed.h"
#include "db-manager.h"
#include "aradogui.h"
#include "deliberate.h"
#include <QDesktopServices>
#include <QTableWidgetItem>
#include <QList>
#include <QSet>
#include <QTimer>
#include <QDebug>

using namespace deliberate;

namespace arado
{

RssList::RssList (QWidget *parent)
  :QWidget (parent),
   dbm (0),
   changedSomething (false),
   newItems()
{
  ui.setupUi (this);
  hide ();
  Connect ();
}

void
RssList::Show ()
{
  ListNewItems ();
  ListFeeds ();
  show ();
}

void
RssList::Hide ()
{
  hide ();
}

void
RssList::Connect ()
{
  connect (ui.newButton, SIGNAL (clicked()), this, SLOT (DoAdd()));
  connect (ui.deleteButton, SIGNAL (clicked()), this, SLOT (DoDelete()));
  connect (ui.closeButton1, SIGNAL (clicked()), this, SLOT (DoClose()));
  connect (ui.closeButton2, SIGNAL (clicked()), this, SLOT (DoClose()));
  connect (ui.saveButton, SIGNAL (clicked()), this, SLOT (DoSave()));

  /* Hide Advanced gui */
  bool showDetails (true); 
  showDetails = Settings().value ("rssview/advanced",showDetails).toBool();
  Settings().setValue ("rssview/advanced",showDetails);
  ui.rsseditadvancedview->setChecked (showDetails);
  rsseditadvancedview(showDetails);
  connect(ui.rsseditadvancedview, SIGNAL(toggled(bool)), 
                                  this, SLOT(rsseditadvancedview(bool)));
  
  connect (ui.rssitemTable, SIGNAL (cellClicked(int,int)), this,
             SLOT (ListNewItemClicked(int,int)) );
  connect (ui.reloadButton, SIGNAL (clicked()), this,
             SLOT (ListNewItems()) );

}

void
RssList::DoClose ()
{
  ui.feedTable->clearContents ();
  Hide ();
  emit Closed (changedSomething);
  changedSomething = false;
}

void
RssList::DoAdd ()
{
  qDebug () << "RssList  DoAdd";
  int newrow = ui.feedTable->rowCount();
  qDebug () << " RssList add Item row " << newrow;
  ui.feedTable->setRowCount (newrow+1);
  QTableWidgetItem * nickItem = new QTableWidgetItem (tr("New Feed"));
  ui.feedTable->setItem (newrow, 0, nickItem);
  QTableWidgetItem * urlItem = new QTableWidgetItem (tr("http://"));
  ui.feedTable->setItem (newrow, 1, urlItem);
  ui.feedTable->scrollToBottom ();
  ui.feedTable->editItem (nickItem);
}

void
RssList::DoDelete ()
{
  qDebug () << "RssList   DoDelete";
  if (dbm == 0) {
    return;
  }
  QSet <int> removeRows;
  QList <QTableWidgetItem*> removeItems = ui.feedTable->selectedItems();
  for (int i=0; i<removeItems.size(); i++) {
    removeRows.insert (removeItems.at(i)->row());
  }
  QSet<int>::iterator rit = removeRows.begin();
  while (rit != removeRows.end()) {
    int row = *rit;
    QTableWidgetItem * nickItem = ui.feedTable->item (row,0);
    if (nickItem) {
      dbm->RemoveFeed (nickItem->text());
    }
    rit++;
  }
  ListFeeds ();
  changedSomething = true;
}

void
RssList::DoSave ()
{
  qDebug () << "RssList  DoSave";
  if (dbm == 0) {
    return;
  }
  QSet <int> saveRows;
  QList <QTableWidgetItem*> saveItems = ui.feedTable->selectedItems();
  for (int i=0; i<saveItems.size(); i++) {
    saveRows.insert (saveItems.at(i)->row());
  }
  QSet<int>::iterator sit = saveRows.begin();
  while (sit != saveRows.end()) {
    int row = *sit;
    QTableWidgetItem * nickItem = ui.feedTable->item (row,0);
    QTableWidgetItem * urlItem = ui.feedTable->item (row,1);
    if (nickItem && urlItem) {
      dbm->WriteFeed (nickItem->text(),
                      QUrl (urlItem->text()));
    }
    sit++;
  }
  ui.feedTable->clearSelection ();
  changedSomething = true;
}

void
RssList::ListNewItems ()
{
  newItems.clear();
  dbm->GetNewFeedItems(newItems, 1000);
  qDebug() << "RssList::ListNewItems count:" << newItems.count();
  ui.rssitemTable->clearContents();
  ui.rssitemTable->setRowCount (0);
  if (dbm) {
    QList<AradoUrl>::const_iterator i;
    for (i = newItems.constBegin(); i != newItems.constEnd(); ++i) {
      ListNewItem(*i);
    }
  }
}

void
RssList::ListNewItem (const AradoUrl &url)
{
  int newrow = ui.rssitemTable->rowCount();
  ui.rssitemTable->setRowCount (newrow+1);

  QIcon icon=QIcon(QPixmap(":/images/kugar.png"));
  QTableWidgetItem * browse = new QTableWidgetItem( icon,"", int (Cell_Kugar));
  ui.rssitemTable->setItem (newrow, 0,browse);

  QTableWidgetItem * nickItem = new QTableWidgetItem (url.Description(),
                                                int (Cell_Desc));
  ui.rssitemTable->setItem (newrow, 1, nickItem);
  QTableWidgetItem * urlItem = new QTableWidgetItem (url.Url().toString(),
                                                int (Cell_Url));
  ui.rssitemTable->setItem (newrow, 2, urlItem);
}

void
RssList::ListNewItemClicked(int row,int col) 
{
  qDebug() << "ListNewItemClicked: " << row;
  if (dbm && row<newItems.count()) {
    CellType tipo (Cell_None);
    const AradoUrl &url=  newItems.at(row);
    QTableWidgetItem * cell = ui.rssitemTable->item (row,col);
    if (cell) {
      tipo = CellType (cell->type());
    }
    if (tipo == Cell_Kugar) {
      QDesktopServices::openUrl (url.Url());
    }
    QString hash=QString(url.Hash());
    dbm->DeleteNewFeedItem(hash);
    ListNewItems ();
  }
}

void
RssList::ListFeeds ()
{
  qDebug () << "RssList List Feeds dbm " << dbm;
  AradoFeedList feeds;
  if (dbm) {
    ui.feedTable->clearContents ();
    ui.feedTable->setRowCount (0);
    feeds = dbm->GetFeeds ();
    int nf = feeds.size();
    for (int f=0; f<nf; f++) {
      ListFeed (feeds.at(f));
    }
  }
}

void
RssList::ListFeed (const AradoFeed & feed)
{
  int newrow = ui.feedTable->rowCount();
  ui.feedTable->setRowCount (newrow+1);
  QTableWidgetItem * nickItem = new QTableWidgetItem (feed.Nick());
  ui.feedTable->setItem (newrow, 0, nickItem);
  QTableWidgetItem * urlItem = new QTableWidgetItem (feed.Url().toString());
  ui.feedTable->setItem (newrow, 1, urlItem);
}

void RssList::rsseditadvancedview(bool show)
{
  Settings().setValue ("rssview/advanced",show);
  ui.saveButton->setVisible(show);
  ui.closeButton2->setVisible(show);
  ui.deleteButton->setVisible(show);
  ui.newButton->setVisible(show);
  ui.feedTable->setVisible(show);
  ui.splitter->setCollapsible (0, false);

  QList<int> splitter_sizes;
  splitter_sizes << 1;
  if (show) {
    splitter_sizes << 1;
  } else {
    splitter_sizes << 0;
  }
  ui.splitter->setSizes(splitter_sizes);
}

} // namespace
