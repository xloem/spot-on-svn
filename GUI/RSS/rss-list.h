#ifndef RSS_LIST_H
#define RSS_LIST_H

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
#include <QWidget>
#include "ui_rss-list.h"
#include "arado-url.h"

class QTimer;

namespace arado
{

class DBManager;
class AradoFeed;

class RssList : public QWidget
{
Q_OBJECT

public:

  RssList (QWidget * parent=0);
  
  void SetDB (DBManager *db) { dbm = db; }

  void Show ();
  void Hide ();

private slots:

  void  DoAdd ();
  void  DoDelete ();
  void  DoClose ();
  void  DoSave ();
  void  rsseditadvancedview(bool show);
  void  ListNewItemClicked(int row,int col);
  void  ListNewItems ();

signals:

  void Closed (bool changed);

private:

  enum CellType {
    Cell_None = 0,
    Cell_Kugar = 1,
    Cell_Desc = 2,  
    Cell_Url = 3
  };

  void Connect ();
  void ListFeeds ();
  void ListFeed (const AradoFeed & feed);
  void ListNewItem (const AradoUrl &url);

  Ui_RssFeedList  ui;
  DBManager      *dbm;
  bool            changedSomething;
  QList<AradoUrl> newItems;

};

} // namespace

#endif