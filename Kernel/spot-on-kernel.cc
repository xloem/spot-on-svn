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

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QtCore/qmath.h>

extern "C"
{
#include "LibSpotOn/libspoton.h"
}

extern "C"
{
#include <fcntl.h>
#ifdef Q_OS_WIN32
#include <process.h>
#endif
#include <signal.h>
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
#include <unistd.h>
#endif
}

#include "Common/spot-on-common.h"
#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"
#include "spot-on-listener.h"
#include "spot-on-neighbor.h"

QCache<QByteArray, char *> spoton_kernel::s_messagingCache;
QHash<QString, QVariant> spoton_kernel::s_settings;
spoton_gcrypt *spoton_kernel::s_crypt1 = 0;
spoton_gcrypt *spoton_kernel::s_crypt2 = 0;

static void sig_handler(int signum)
{
  Q_UNUSED(signum);

  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_handle_t libspotonHandle;

  if(libspoton_init(sharedPath.toStdString().c_str(),
		    &libspotonHandle) == LIBSPOTON_ERROR_NONE)
#ifdef Q_OS_WIN32
    libspoton_deregister_kernel(_getpid(), &libspotonHandle);
#else
    libspoton_deregister_kernel(getpid(), &libspotonHandle);
#endif

  libspoton_close(&libspotonHandle);

  /*
  ** _Exit() and _exit() may be safely called from signal handlers.
  */

  _Exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  QList<int> list;
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
  struct sigaction act;
#endif
  list << SIGABRT
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
       << SIGBUS
#endif
       << SIGFPE
       << SIGILL
       << SIGINT
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
       << SIGKILL
       << SIGQUIT
#endif
       << SIGSEGV
       << SIGTERM;

  while(!list.isEmpty())
    {
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
      act.sa_handler = sig_handler;
      sigemptyset(&act.sa_mask);
      act.sa_flags = 0;
      sigaction(list.takeFirst(), &act, (struct sigaction *) 0);
#else
      signal(list.takeFirst(), sig_handler);
#endif
    }

#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
  /*
  ** Ignore SIGPIPE.
  */

  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(SIGPIPE, &act, (struct sigaction *) 0);
#endif

  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;
  libspoton_handle_t libspotonHandle;

  if((err = libspoton_init(sharedPath.toStdString().c_str(),
			   &libspotonHandle)) == LIBSPOTON_ERROR_NONE)
    err = libspoton_register_kernel(QCoreApplication::applicationPid(),
				    false, // Do not force registration.
				    &libspotonHandle);

  libspoton_close(&libspotonHandle);

  if(err == LIBSPOTON_ERROR_NONE)
    {
      QCoreApplication qapplication(argc, argv);

      QCoreApplication::setApplicationName("Spot-On");
      QCoreApplication::setOrganizationName("Spot-On");
      QCoreApplication::setOrganizationDomain("spot-on.sf.net");
      QCoreApplication::setApplicationVersion(SPOTON_VERSION_STR);
      QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
			 spoton_misc::homePath());
      QSettings::setDefaultFormat(QSettings::IniFormat);
      Q_UNUSED(new spoton_kernel());
      return qapplication.exec();
    }
  else
    return EXIT_FAILURE;
}

spoton_kernel::spoton_kernel(void):QObject(0)
{
  QDir().mkdir(spoton_misc::homePath());
  cleanupDatabases();

  /*
  ** The user interface doesn't yet have a means of preparing advanced
  ** options.
  */

  QSettings settings;

  if(!settings.contains("kernel/maximum_number_of_bytes_buffered_by_neighbor"))
    settings.setValue("kernel/maximum_number_of_bytes_buffered_by_neighbor",
		      25000);

  if(!settings.contains("kernel/ttl_0000"))
    settings.setValue("kernel/ttl_0000", 16);

  if(!settings.contains("kernel/ttl_0010"))
    settings.setValue("kernel/ttl_0010", 16);

  if(!settings.contains("kernel/ttl_0013"))
    settings.setValue("kernel/ttl_0013", 16);

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  connect(&m_controlDatabaseTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPollDatabase(void)));
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimerExpired(void)));
  m_controlDatabaseTimer.start(2500);
  m_statusTimer.start(15000);
  m_guiServer = new spoton_gui_server(this);
  connect(m_guiServer,
	  SIGNAL(messageReceivedFromUI(const qint64,
				       const QByteArray &,
				       const QByteArray &)),
	  this,
	  SLOT(slotMessageReceivedFromUI(const qint64,
					 const QByteArray &,
					 const QByteArray &)));
  connect
    (m_guiServer,
     SIGNAL(publicKeyReceivedFromUI(const qint64,
				    const QByteArray &,
				    const QByteArray &)),
     this,
     SLOT(slotPublicKeyReceivedFromUI(const qint64,
				      const QByteArray &,
				      const QByteArray &)));
  connect
    (m_guiServer,
     SIGNAL(publicKeyReceivedFromUI(const qint64,
				    const QByteArray &,
				    const QByteArray &,
				    const QByteArray &)),
     this,
     SLOT(slotPublicKeyReceivedFromUI(const qint64,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &)));
  m_settingsWatcher.addPath(settings.fileName());
  connect(&m_settingsWatcher,
	  SIGNAL(fileChanged(const QString &)),
	  this,
	  SLOT(slotSettingsChanged(const QString &)));
}

spoton_kernel::~spoton_kernel()
{
  cleanup();
  cleanupDatabases();
  spoton_misc::logError
    (QString("Kernel %1 about to exit.").
     arg(QCoreApplication::applicationPid()));
  QCoreApplication::instance()->quit();
}

void spoton_kernel::cleanup(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_handle_t libspotonHandle;

  if(libspoton_init(sharedPath.toStdString().c_str(),
		    &libspotonHandle) == LIBSPOTON_ERROR_NONE)
    libspoton_deregister_kernel(QCoreApplication::applicationPid(),
				&libspotonHandle);

  libspoton_close(&libspotonHandle);
}

void spoton_kernel::cleanupDatabases(void)
{
  m_controlDatabaseTimer.stop();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("UPDATE symmetric_keys SET status = 'offline'"))
	  db.commit();

	/*
	** Delete symmetric keys that were not completely shared.
	*/

	if(query.exec("DELETE FROM symmetric_keys WHERE neighbor_oid <> -1"))
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("DELETE FROM kernel_gui_server"))
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("UPDATE listeners SET connections = 0, "
		      "status = 'off' WHERE status = 'online' AND "
		      "status_control <> 'deleted'"))
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("UPDATE neighbors SET local_ip_address = '127.0.0.1', "
		      "local_port = 0, "
		      "status = 'disconnected' WHERE "
		      "status = 'connected' AND status_control <> 'deleted'"))
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");
}

void spoton_kernel::slotPollDatabase(void)
{
  spoton_misc::prepareDatabases();
  copyPublicKey();
  prepareListeners();
  prepareNeighbors();
  checkForTermination();
}

void spoton_kernel::prepareListeners(void)
{
  if(!s_crypt1)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT ip_address, port, scope_id, status_control, "
		      "maximum_clients, OID FROM listeners"))
	  while(query.next())
	    {
	      QPointer<spoton_listener> listener = 0;
	      qint64 id = query.value(5).toLongLong();

	      if(!m_listeners.contains(id))
		{
		  QList<QByteArray> list;

		  for(int i = 0; i < 3; i++)
		    {
		      QByteArray bytes;
		      bool ok = true;

		      bytes = s_crypt1->
			decrypted(QByteArray::fromBase64(query.
							 value(i).
							 toByteArray()),
				  &ok);

		      if(ok)
			list.append(bytes);
		      else
			break;
		    }

		  if(list.size() == 3)
		    listener = new spoton_listener
		      (list.at(0).constData(),
		       list.at(1).constData(),
		       list.at(2).constData(),
		       query.value(4).toInt(),
		       query.value(5).toLongLong(),
		       this);

		  if(listener)
		    {
		      connect
			(listener,
			 SIGNAL(newNeighbor(QPointer<spoton_neighbor>)),
			 this,
			 SLOT(slotNewNeighbor(QPointer<spoton_neighbor>)));
		      m_listeners.insert(id, listener);
		    }
		}
	      else
		{
		  listener = m_listeners.value(id);

		  if(listener)
		    {
		      QString state(query.value(3).toString().trimmed());

		      if(state == "deleted")
			{
			  m_listeners.remove(id);
			  listener->close();
			  listener->deleteLater();
			}
		    }
		  else
		    m_listeners.remove(id);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");

  for(int i = m_listeners.keys().size() - 1; i >= 0; i--)
    if(!m_listeners.value(m_listeners.keys().at(i)))
      {
	spoton_misc::logError
	  (QString("spoton_kernel::prepareListeners(): "
		   "listener %1 "
		   " may have been deleted from the listeners table by an"
		   " external event. Purging listener from the listeners "
		   "hash.").
	   arg(m_listeners.keys().at(i)));
	m_listeners.remove(m_listeners.keys().at(i));
      }
}

void spoton_kernel::prepareNeighbors(void)
{
  if(!s_crypt1)
    return;

  bool allOffline = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, remote_port, scope_id, "
		      "status_control, OID FROM neighbors"))
	  while(query.next())
	    {
	      QPointer<spoton_neighbor> neighbor = 0;
	      qint64 id = query.value(4).toLongLong();

	      if(!m_neighbors.contains(id))
		{
		  QList<QByteArray> list;

		  for(int i = 0; i < 3; i++)
		    {
		      QByteArray bytes;
		      bool ok = true;

		      bytes = s_crypt1->
			decrypted(QByteArray::fromBase64(query.
							 value(i).
							 toByteArray()),
				  &ok);

		      if(ok)
			list.append(bytes);
		      else
			break;
		    }

		  if(list.size() == 3)
		    neighbor = new spoton_neighbor
		      (list.at(0).constData(),
		       list.at(1).constData(),
		       list.at(2).constData(),
		       query.value(4).toLongLong(),
		       this);

		  if(neighbor)
		    {
		      connectSignalsToNeighbor(neighbor);
		      m_neighbors.insert(id, neighbor);
		    }
		}
	      else
		{
		  neighbor = m_neighbors.value(id);

		  if(neighbor)
		    {
		      QString state(query.value(3).toString().trimmed());

		      if(state == "deleted")
			{
			  m_neighbors.remove(id);
			  neighbor->close();
			  neighbor->deleteLater();
			}
		    }
		  else
		    m_neighbors.remove(id);
		}

	      if(neighbor)
		if(neighbor->state() == QAbstractSocket::ConnectedState)
		  allOffline = false;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");

  for(int i = m_neighbors.keys().size() - 1; i >= 0; i--)
    if(!m_neighbors.value(m_neighbors.keys().at(i)))
      {
	spoton_misc::logError
	  (QString("spoton_kernel::prepareNeighbors(): "
		   "neighbor %1 "
		   " may have been deleted from the neighbors table by an"
		   " external event. Purging neighbor from the neighbors "
		   "hash.").arg(m_neighbors.keys().at(i)));
	m_neighbors.remove(m_neighbors.keys().at(i));
      }

  if(allOffline)
    s_messagingCache.clear();
}
void spoton_kernel::checkForTermination(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  bool registered = false;
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;
  libspoton_handle_t libspotonHandle;

  if((err = libspoton_init(sharedPath.toStdString().c_str(),
			   &libspotonHandle)) == LIBSPOTON_ERROR_NONE)
    registered = QCoreApplication::applicationPid() ==
      libspoton_registered_kernel_pid(&libspotonHandle);

  libspoton_close(&libspotonHandle);

  if(!registered)
    {
      for(int i = 0; i < m_listeners.keys().size(); i++)
	{
	  QPointer<spoton_listener> listener = m_listeners.take
	    (m_listeners.keys().at(i));

	  if(listener)
	    {
	      listener->close();
	      listener->deleteLater();
	    }
	}

      for(int i = 0; i < m_neighbors.keys().size(); i++)
	{
	  QPointer<spoton_neighbor> neighbor = m_neighbors.take
	    (m_neighbors.keys().at(i));

	  if(neighbor)
	    {
	      neighbor->close();
	      neighbor->deleteLater();
	    }
	}

      deleteLater();
    }
}

void spoton_kernel::slotNewNeighbor(QPointer<spoton_neighbor> neighbor)
{
  if(neighbor)
    {
      qint64 id = neighbor->id();

      if(!m_neighbors.contains(id))
	{
	  neighbor->setParent(this);
	  connectSignalsToNeighbor(neighbor);
	  m_neighbors.insert(id, neighbor);
	}
    }
}

void spoton_kernel::copyPublicKey(void)
{
  QByteArray publicKey;
  bool ok = true;

  if(s_crypt1)
    publicKey = s_crypt1->publicKey(&ok);
  else
    ok = false;

  if(ok)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.exec("PRAGMA synchronous = OFF");
	    query.prepare("INSERT INTO public_keys (key) VALUES (?)");
	    query.bindValue(0, publicKey);

	    if(query.exec())
	      db.commit();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("kernel");
    }
}

void spoton_kernel::slotMessageReceivedFromUI(const qint64 oid,
					      const QByteArray &name,
					      const QByteArray &message)
{
  if(!s_crypt1)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT symmetric_key, symmetric_key_algorithm "
		      "FROM symmetric_keys WHERE OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  if(query.next())
	    {
	      QByteArray hash;
	      QByteArray symmetricKey
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      QByteArray symmetricKeyAlgorithm
		(QByteArray::fromBase64(query.value(1).toByteArray()));
	      bool ok = true;

	      symmetricKey = s_crypt1->decrypted(symmetricKey, &ok);

	      if(ok)
		symmetricKeyAlgorithm = s_crypt1->decrypted
		  (symmetricKeyAlgorithm, &ok);

	      if(ok)
		hash = spoton_gcrypt::sha512Hash
		  (name.leftJustified(spoton_send::NAME_MAXIMUM_LENGTH,
				      '\n') + message, &ok);

	      if(ok)
		{
		  QByteArray data;

		  data.append(hash.toHex());
		  data.append
		    (name.leftJustified(spoton_send::NAME_MAXIMUM_LENGTH,
					'\n'));
		  data.append(message);

		  spoton_gcrypt crypt(symmetricKeyAlgorithm,
				      QString(""),
				      symmetricKey,
				      0,
				      0,
				      QString(""));

		  data = crypt.encrypted(data, &ok);

		  if(ok)
		    {
		      QByteArray publicKey(s_crypt1->publicKey(&ok));

		      if(ok)
			hash = s_crypt1->sha512Hash(publicKey, &ok);
		    }

		  if(ok)
		    {
		      char c = 0;
		      short ttl = s_settings.value
			("kernel/ttl_0000", 16).toInt();

		      memcpy(&c, static_cast<void *> (&ttl), 1);
		      data.prepend(hash.toHex());
		      data.prepend(c);

		      if(s_settings.value("gui/chatSendMethod",
					  "Artificial_GET").toString().
			 trimmed() == "Artificial_GET")
			emit sendMessage
			  (spoton_send::message0000(data,
						    spoton_send::
						    ARTIFICIAL_GET));
		      else
			emit sendMessage
			  (spoton_send::message0000(data,
						    spoton_send::
						    NORMAL_POST));
		    }
		}
	    }

	db.close();
      }
  }

  QSqlDatabase::removeDatabase("kernel");
}

void spoton_kernel::slotPublicKeyReceivedFromUI(const qint64 oid,
						const QByteArray &name,
						const QByteArray &publicKey)
{
  QByteArray data(spoton_send::message0011(name, publicKey));

  if(m_neighbors.contains(oid))
    {
      if(m_neighbors[oid]->write(data.constData(), data.length()) !=
	 data.length())
	spoton_misc::logError
	  ("spoton_kernel::slotPublicKeyReceivedFromUI(): "
	   "write() failure.");
      else
	m_neighbors[oid]->flush();
    }
  else
    spoton_misc::logError
      (QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
	       "neighbor %1 not found in m_neighbors.").arg(oid));
}

void spoton_kernel::slotPublicKeyReceivedFromUI
(const qint64 oid,
 const QByteArray &publicKey,
 const QByteArray &symmetricKey,
 const QByteArray &symmetricKeyAlgorithm)
{
  if(m_neighbors.contains(oid))
    m_neighbors[oid]->sharePublicKey
      (publicKey, symmetricKey, symmetricKeyAlgorithm);
  else
    spoton_misc::logError
      (QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
	       "neighbor %1 not found in m_neighbors.").arg(oid));
}

void spoton_kernel::slotSettingsChanged(const QString &path)
{
  Q_UNUSED(path);
  s_settings.clear();

  QSettings settings;

  if(!settings.contains("kernel/maximum_number_of_bytes_buffered_by_neighbor"))
    settings.setValue("kernel/maximum_number_of_bytes_buffered_by_neighbor",
		      25000);

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));
}

void spoton_kernel::connectSignalsToNeighbor(spoton_neighbor *neighbor)
{
  if(!neighbor)
    return;

  connect(neighbor,
	  SIGNAL(receivedChatMessage(const QByteArray &)),
	  m_guiServer,
	  SLOT(slotReceivedChatMessage(const QByteArray &)));
  connect(neighbor,
	  SIGNAL(receivedChatMessage(const QByteArray &,
				     const qint64)),
	  this,
	  SIGNAL(receivedChatMessage(const QByteArray &,
				     const qint64)));
  connect(neighbor,
	  SIGNAL(receivedPublicKey(const QByteArray &,
				   const qint64)),
	  this,
	  SIGNAL(receivedPublicKey(const QByteArray &,
				   const qint64)));
  connect(neighbor,
	  SIGNAL(receivedStatusMessage(const QByteArray &,
				       const qint64)),
	  this,
	  SIGNAL(receivedStatusMessage(const QByteArray &,
				       const qint64)));
  connect(this,
	  SIGNAL(receivedChatMessage(const QByteArray &,
				     const qint64)),
	  neighbor,
	  SLOT(slotReceivedChatMessage(const QByteArray &,
				       const qint64)));
  connect(this,
	  SIGNAL(receivedPublicKey(const QByteArray &,
				   const qint64)),
	  neighbor,
	  SLOT(slotReceivedPublicKey(const QByteArray &,
				     const qint64)));
  connect(this,
	  SIGNAL(receivedStatusMessage(const QByteArray &,
				       const qint64)),
	  neighbor,
	  SLOT(slotReceivedStatusMessage(const QByteArray &,
					 const qint64)));
  connect(this,
	  SIGNAL(sendMessage(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendMessage(const QByteArray &)));
  connect(this,
	  SIGNAL(sendStatus(const QList<QByteArray> &)),
	  neighbor,
	  SLOT(slotSendStatus(const QList<QByteArray> &)));
}

void spoton_kernel::slotStatusTimerExpired(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE symmetric_keys SET "
		      "status = 'offline' WHERE "
		      "strftime('%s', ?) - "
		      "strftime('%s', last_status_update) > ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue
	  (1, 2 * qCeil(m_statusTimer.interval() / 1000.0));

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");

  if(!s_crypt1)
    return;

  /*
  ** Do we have any interfaces attached to the kernel?
  */

  QByteArray publicKey;
  QByteArray publicKeyHash;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(ok)
    publicKeyHash = s_crypt1->sha512Hash(publicKey, &ok);
  else
    return;

  if(!ok)
    return;

  QByteArray status("offline");
  QList<QByteArray> list;

  if(!m_guiServer->findChildren<QTcpSocket *> ().isEmpty())
    status = s_settings.value("gui/my_status", "online").
      toByteArray().toLower();

  /*
  ** Retrieve the symmetric bundle of each participant.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("SELECT symmetric_key, symmetric_key_algorithm "
		      "FROM symmetric_keys WHERE neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray symmetricKey
		(QByteArray::fromBase64(query.value(0).
					toByteArray()));
	      QByteArray symmetricKeyAlgorithm
		(QByteArray::fromBase64(query.value(1).
					toByteArray()));

	      ok = true;
	      symmetricKey = s_crypt1->decrypted(symmetricKey, &ok);

	      if(ok)
		symmetricKeyAlgorithm =
		  s_crypt1->decrypted(symmetricKeyAlgorithm, &ok);

	      if(ok)
		{
		  QByteArray hash;

		  hash = spoton_gcrypt::sha512Hash(status, &ok);

		  if(ok)
		    {
		      spoton_gcrypt crypt(symmetricKeyAlgorithm,
					  QString(""),
					  symmetricKey,
					  0,
					  0,
					  QString(""));

		      QByteArray encrypted;

		      encrypted.append(hash.toHex()).append(status);
		      encrypted = crypt.encrypted(encrypted, &ok);

		      if(ok)
			{
			  char c = 0;
			  short ttl = s_settings.value
			    ("kernel/ttl_0013", 16).toInt();

			  memcpy(&c, static_cast<void *> (&ttl), 1);
			  encrypted.prepend(publicKeyHash.toHex());
			  encrypted.prepend(c);
			  list.append(encrypted);
			}
		    }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("kernel");
  emit sendStatus(list);
}
