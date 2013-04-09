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

#include "addfeed.h"
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QDomDocument>
#include <QWebPage>
#include <QWebFrame>
#include <QWebView>
#include "networkaccessmanager.h"

namespace arado
{

AddRssFeed::AddRssFeed(QObject *parent) :
  QObject(parent)
{
  qnam=new NetworkAccessManager(parent);
}

void
AddRssFeed::httpFinished (QNetworkReply *reply)
{
  QDomDocument dom;
  dom.setContent(reply);
  newUrls.clear ();
  QDomNodeList rssList = dom.elementsByTagName ("item");
  QDomNodeList atomList = dom.elementsByTagName ("entry");
  ParseItems (rssList);
  ParseItems (atomList);
  int count = newUrls.count();
  if (count > 0) {
    db->StartTransaction();
    for (int u=0; u<count; u++) {
      AradoUrl newUrl (newUrls.at(u));
      db->AddUrl (newUrl);
    }
    db->CloseTransaction();
  }
  this->reply->deleteLater();
  this->reply=NULL;
}

void
AddRssFeed::ParseItems (QDomNodeList & itemList)
{
  for (unsigned int n=0; n<itemList.length(); n++) {
    QDomNode node=itemList.item(n);
    QString title, link, description;
    for (unsigned int c=0; c<node.childNodes().length(); c++) {
      QDomNode child=node.childNodes().item(c);
      QString name = child.nodeName().toLower();

      if (name == "title") {
        title=child.firstChild().nodeValue();

      } else if (name == "description") {
        description = child.firstChild().nodeValue ();
      } else if (name == "summary") {
        description = child.firstChild().nodeValue ();

      } else if (name == "link") {
        link=child.firstChild().nodeValue();

         int firstUrlPos = link.indexOf ("url=");
         QString rightUrl;
         if (firstUrlPos > 4) {
            rightUrl = link.mid (firstUrlPos+4, -1);
            link = rightUrl;
          }


      }
    }
    if (title.length()>0 && link.length()>0) {
      AradoUrl  newurl;
      newurl.SetUrl (link);
      newurl.SetDescription(title);
      newurl.ComputeHash ();
      if (description.length() > 0) {
        MakeKeywords (newurl, description);
      }
      if (newurl.IsValid ()) {
        newUrls.append (newurl);
        if(db->AddUrl (newurl) && storeNewItems) {
            db->AddNewFeedItem(newurl);
        }
      }
    }
  }
}

void
AddRssFeed::PollFeed (QString urlText, bool saveNewItems)
{
  storeNewItems = saveNewItems;
  QUrl feedUrl=QUrl (urlText, QUrl::TolerantMode);

  QNetworkRequest request (feedUrl);

  reply=qnam->get(request);

  connect (qnam, SIGNAL(finished(QNetworkReply *)),
          this, SLOT(httpFinished(QNetworkReply *)));
}

bool
AddRssFeed::LongerString (const QString & s1, const QString & s2)
{
  return s1.length() > s2.length();
}

void
AddRssFeed::MakeKeywords (AradoUrl & aurl, const QString & description)
{
  QWebView htmlBuffer;
  htmlBuffer.setHtml (description);
  
  QWebPage *page = htmlBuffer.page();
  if (page) {
    QWebFrame * frame = page->mainFrame();
    if (frame) {
      QStringList words = frame->toPlainText().split(QRegExp("\\s+"), 
                                      QString::SkipEmptyParts);
      qSort (words.begin(), words.end(), LongerString);
      int nw = words.count();
      for (int w=0; w < nw && w < 10; w++) {
        aurl.AddKeyword (words.at(w));
      }
    }
  }
}

} // namespace

