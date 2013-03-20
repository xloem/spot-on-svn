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

#include <QDir>

#include "Common/spot-on-misc.h"
#include "spot-on-logviewer.h"

spoton_logviewer::spoton_logviewer(void):QMainWindow()
{
  m_position = 0;
  ui.setupUi(this);
#ifdef Q_OS_MAC
  setAttribute(Qt::WA_MacMetalStyle, true);
  statusBar()->setSizeGripEnabled(false);
#endif
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.action_Empty_Log,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(2500);
}

void spoton_logviewer::slotClose(void)
{
  close();
}

void spoton_logviewer::slotClear(void)
{
  m_position = 0;
  QFile::remove
    (spoton_misc::homePath() + QDir::separator() + "error_log.dat");
  ui.log->clear();
}

void spoton_logviewer::show(QWidget *parent)
{
  int X = 0;
  int Y = 0;
  QPoint p(parent->pos());

  if(parent->width() >= width())
    X = p.x() + (parent->width() - width()) / 2;
  else
    X = p.x() - (width() - parent->width()) / 2;

  if(parent->height() >= height())
    Y = p.y() + (parent->height() - height()) / 2;
  else
    Y = p.y() - (height() - parent->height()) / 2;

  move(X, Y);
  QMainWindow::show();
  raise();
}

void spoton_logviewer::slotTimeout(void)
{
  QFile file
    (spoton_misc::homePath() + QDir::separator() + "error_log.dat");

  if(file.open(QIODevice::ReadOnly))
    {
      if(file.size() < m_position)
	{
	  m_position = 0;
	  ui.log->clear();
	}

      file.seek(m_position);

      if(!file.atEnd())
	{
	  ui.log->append(file.readAll().trimmed());
	  ui.log->append(QString());
	  ui.log->textCursor().movePosition(QTextCursor::End);
	  ui.log->ensureCursorVisible();
	  m_position = file.pos();
	}

      file.close();
    }
  else
    {
      m_position = 0;
      ui.log->clear();
    }
}
