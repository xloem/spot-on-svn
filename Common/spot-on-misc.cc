/*
** Copyright (c) 2012, 2013 Alexis Megas
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

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QString>
#include <QtDebug>

#include "spot-on-misc.h"

QString spoton_misc::homePath(void)
{
  QString homepath(qgetenv("SPOTON_HOME").trimmed());

  if(homepath.isEmpty())
    return QDir::homePath() + QDir::separator() + ".spot-on";
  else
    return homepath;
}

bool spoton_misc::isGnome(void)
{
  QString session(qgetenv("DESKTOP_SESSION").toLower().trimmed());

  if(session == "gnome" || session == "ubuntu")
    return true;
  else
    return false;
}

void spoton_misc::prepareDatabases(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "prepare");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS symmetric_keys ("
		   "name TEXT NOT NULL DEFAULT 'unknown', "
		   "symmetric_key BLOB, "
		   "symmetric_key_algorithm TEXT, "
		   "public_key TEXT NOT NULL, "
		   "public_key_hash TEXT PRIMARY KEY NOT NULL, "
		   "neighbor_oid INTEGER DEFAULT -1)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("prepare");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "prepare");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS kernel_gui_server ("
		   "port INTEGER PRIMARY KEY NOT NULL)");
	query.exec("CREATE TRIGGER IF NOT EXISTS kernel_gui_server_trigger "
		   "BEFORE INSERT ON kernel_gui_server "
		   "BEGIN "
		   "DELETE FROM kernel_gui_server; "
		   "END");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("prepare");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "prepare");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS listeners ("
		   "ip_address TEXT NOT NULL, "
		   "port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'off', "
		   "status_control TEXT NOT NULL DEFAULT 'online', "
		   "connections INTEGER NOT NULL DEFAULT 0, "
		   "maximum_clients INTEGER NOT NULL DEFAULT 5, "
		   "hash TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("prepare");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "prepare");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS neighbors ("
		   "local_ip_address TEXT NOT NULL, "
		   "local_port TEXT NOT NULL, "
		   "remote_ip_address TEXT NOT NULL, "
		   "remote_port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'disconnected', "
		   "status_control TEXT NOT NULL DEFAULT 'connected', "
		   "sticky INTEGER NOT NULL DEFAULT 1, "
		   "hash TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("prepare");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "prepare");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS public_keys ("
		   "key TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("prepare");
}

void spoton_misc::logError(const QString &error)
{
  QFile file(homePath() + QDir::separator() + "error_log.dat");

  if(file.open(QIODevice::Append | QIODevice::WriteOnly))
    {
      QDateTime now(QDateTime::currentDateTime());
#ifdef Q_OS_WIN32
      QString eol("\r\n");
#else
      QString eol('\n');
#endif

      file.write(now.toString().toLatin1());
      file.write(eol.toLatin1());
      file.write(error.toLatin1());
      file.write(eol.toLatin1());
      file.write(eol.toLatin1());
    }

  file.close();
}
