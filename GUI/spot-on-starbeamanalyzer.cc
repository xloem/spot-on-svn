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

#include <QCheckBox>
#include <QKeyEvent>
#include <QTableWidgetItem>
#include <QtCore>

#include "spot-on-starbeamanalyzer.h"

spoton_starbeamanalyzer::spoton_starbeamanalyzer(void):QMainWindow()
{
  ui.setupUi(this);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
  statusBar()->setSizeGripEnabled(false);
#endif
  ui.tableWidget->setColumnHidden
    (ui.tableWidget->columnCount() - 1, true); // OID
  ui.tableWidget->horizontalHeader()->setSortIndicator(1, Qt::AscendingOrder);
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(this,
	  SIGNAL(updatePercent(QTableWidgetItem *,
			       const QString &,
			       const int)),
	  this,
	  SLOT(slotUpdatePercent(QTableWidgetItem *,
				 const QString &,
				 const int)));
  slotSetIcons();
}

void spoton_starbeamanalyzer::slotClose(void)
{
  close();
}

void spoton_starbeamanalyzer::show(QWidget *parent)
{
  if(parent)
    {
      QPoint p(parent->pos());
      int X = 0;
      int Y = 0;

      if(parent->width() >= width())
	X = p.x() + (parent->width() - width()) / 2;
      else
	X = p.x() - (width() - parent->width()) / 2;

      if(parent->height() >= height())
	Y = p.y() + (parent->height() - height()) / 2;
      else
	Y = p.y() - (height() - parent->height()) / 2;

      move(X, Y);
    }

  QMainWindow::show();
  raise();
}

void spoton_starbeamanalyzer::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_starbeamanalyzer::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().
		  trimmed());

  ui.clear->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
bool spoton_starbeamanalyzer::event(QEvent *event)
{
  if(event)
    if(event->type() == QEvent::WindowStateChange)
      if(windowState() == Qt::WindowNoState)
	{
	  /*
	  ** Minimizing the window on OS 10.6.8 and Qt 5.x will cause
	  ** the window to become stale once it has resurfaced.
	  */

	  hide();
	  show(0);
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif

bool spoton_starbeamanalyzer::add(const QString &fileName,
				  const QString &oid,
				  const QString &pulseSize,
				  const QString &totalSize)
{
  if(fileName.trimmed().isEmpty() || oid.trimmed().isEmpty() ||
     pulseSize.trimmed().isEmpty() || totalSize.trimmed().isEmpty())
    return false;

  if(m_hash.contains(fileName))
    return false;

  ui.tableWidget->setSortingEnabled(false);

  QCheckBox *checkBox = 0;
  QTableWidgetItem *item = 0;
  int row = ui.tableWidget->rowCount();

  ui.tableWidget->setRowCount(row + 1);
  checkBox = new QCheckBox();
  ui.tableWidget->setCellWidget(row, 0, checkBox);
  item = new QTableWidgetItem("0");
  ui.tableWidget->setItem(row, 1, item);
  item = new QTableWidgetItem(pulseSize);
  ui.tableWidget->setItem(row, 2, item);
  item = new QTableWidgetItem(totalSize);
  ui.tableWidget->setItem(row, 3, item);
  item = new QTableWidgetItem(fileName);
  ui.tableWidget->setItem(row, 4, item);
  item = new QTableWidgetItem(oid);
  ui.tableWidget->setItem(row, 5, item);
  ui.tableWidget->setSortingEnabled(true);

  QFuture<void> future = QtConcurrent::run
    (this,
     &spoton_starbeamanalyzer::analyze,
     fileName,
     pulseSize,
     totalSize,
     ui.tableWidget->item(row, 1));

  m_hash.insert(fileName, future);
  return true;
}

void spoton_starbeamanalyzer::analyze(const QString &fileName,
				      const QString &pulseSize,
				      const QString &totalSize,
				      QTableWidgetItem *item)
{
  int ps = pulseSize.toInt();

  if(ps <= 0)
    {
      emit updatePercent(0, fileName, 0);
      return;
    }

  qint64 ts = totalSize.toLongLong();

  if(ts <= 0 || ts <= ps)
    {
      emit updatePercent(0, fileName, 0);
      return;
    }

  QFile file(fileName);

  if(file.open(QIODevice::ReadOnly))
    {
      QByteArray bytes(ps, 0);
      qint64 rc = 0;

      while((rc = file.read(bytes.data(), bytes.length())) > 0)
	{
	  if(bytes.count('0') == bytes.length())
	    {
	      /*
	      ** Potential problem.
	      */
	    }

	  int percent = 100 * static_cast<double> (file.pos()) /
	    static_cast<double> (ts);

	  if(percent > 0 && percent % 10)
	    emit updatePercent(item, fileName, percent);
	}

      file.close();
      emit updatePercent(item, fileName, 100);
    }
  else
    emit updatePercent(item, fileName, 0);
}

void spoton_starbeamanalyzer::slotUpdatePercent(QTableWidgetItem *item,
						const QString &fileName,
						const int percent)
{
  Q_UNUSED(fileName);

  if(item)
    item->setText(QString("%1%").arg(percent));
}
