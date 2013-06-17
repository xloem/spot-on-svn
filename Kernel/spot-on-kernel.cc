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
#include <QNetworkProxy>
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
#include <termios.h>
#include <unistd.h>
#else
#if QT_VERSION >= 0x050000
#include <winsock2.h>
#endif
#include <windows.h>
#endif
}

#include "Common/spot-on-common.h"
#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"
#include "spot-on-listener.h"
#include "spot-on-mailer.h"
#include "spot-on-neighbor.h"
#include "spot-on-shared-reader.h"

QHash<QString, QVariant> spoton_kernel::s_settings;
spoton_gcrypt *spoton_kernel::s_crypt1 = 0;
spoton_gcrypt *spoton_kernel::s_crypt2 = 0;

static void sig_handler(int signum)
{
  Q_UNUSED(signum);

  /*
  ** Resume console input echo.
  */

#ifdef Q_OS_WIN32
  DWORD mode = 0;
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 

  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode | ENABLE_ECHO_INPUT);
#else
  termios oldt;

  tcgetattr(STDIN_FILENO, &oldt);
  oldt.c_lflag |= ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

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
  m_guiServer = 0;
  m_mailer = 0;
  m_sharedReader = 0;
  s_crypt1 = 0;
  s_crypt2 = 0;
  qsrand(QTime(0, 0, 0).secsTo(QTime::currentTime()));
  QDir().mkdir(spoton_misc::homePath());
  spoton_misc::cleanupDatabases();

  /*
  ** The user interface doesn't yet have a means of preparing advanced
  ** options.
  */

  QSettings settings;

  if(!settings.contains("kernel/ttl_0000"))
    settings.setValue("kernel/ttl_0000", 16);

  if(!settings.contains("kernel/ttl_0001a"))
    settings.setValue("kernel/ttl_0001a", 16);

  if(!settings.contains("kernel/ttl_0001b"))
    settings.setValue("kernel/ttl_0001b", 16);

  if(!settings.contains("kernel/ttl_0002"))
    settings.setValue("kernel/ttl_0002", 16);

  if(!settings.contains("kernel/ttl_0010"))
    settings.setValue("kernel/ttl_0010", 16);

  if(!settings.contains("kernel/ttl_0013"))
    settings.setValue("kernel/ttl_0013", 16);

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  QStringList arguments(QCoreApplication::arguments());

  for(int i = 0; i < arguments.size(); i++)
    if(arguments.at(i) == "--passphrase")
      {
	/*
	** Attempt to disable input echo.
	*/

#ifdef Q_OS_WIN32
	DWORD mode = 0;
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 

	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#else
	termios newt;
	termios oldt;

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif
	QString input("");
	QTextStream cin(stdin);
	QTextStream cout(stdout);

	cout << "Passphrase: ";
	cout.flush();
	input = cin.readLine();

#ifdef Q_OS_WIN32
	SetConsoleMode(hStdin, mode);
#else
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

	if(!initializeSecurityContainers(input))
	  {
	    qDebug() << "Invalid passphrase?";
	    deleteLater();
	  }

	break;
      }

  connect(&m_controlDatabaseTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPollDatabase(void)));
  connect(&m_scramblerTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotScramble(void)));
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimerExpired(void)));
  m_controlDatabaseTimer.start(2500);
  m_statusTimer.start(15000);
  m_guiServer = new spoton_gui_server(this);
  m_mailer = new spoton_mailer(this);
  m_sharedReader = new spoton_shared_reader(this);
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
				    const QByteArray &,
				    const QByteArray &,
				    const QByteArray &,
				    const QString &)),
     this,
     SLOT(slotPublicKeyReceivedFromUI(const qint64,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QString &)));
  
  connect(m_guiServer,
	  SIGNAL(retrieveMail(void)),
	  this,
	  SLOT(slotRetrieveMail(void)));
  connect(m_mailer,
	  SIGNAL(sendMail(const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const qint64)),
	  this,
	  SLOT(slotSendMail(const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const qint64)));
  m_settingsWatcher.addPath(settings.fileName());
  connect(&m_settingsWatcher,
	  SIGNAL(fileChanged(const QString &)),
	  this,
	  SLOT(slotSettingsChanged(const QString &)));

  /*
  ** The scrambler implements a very simple idea. If enabled, neighbors will
  ** randomly secrete randomly-encrypted data.
  */

  m_scramblerTimer.setInterval(qrand() % 20000 + 40000);

  if(s_settings.value("gui/scramblerEnabled", false).toBool())
    m_scramblerTimer.start();
}

spoton_kernel::~spoton_kernel()
{
  cleanup();
  spoton_misc::cleanupDatabases();
  delete s_crypt1;
  s_crypt1 = 0;
  delete s_crypt2;
  s_crypt2 = 0;
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

void spoton_kernel::slotPollDatabase(void)
{
  spoton_misc::prepareDatabases();
  prepareListeners();
  prepareNeighbors();
  checkForTermination();
}

void spoton_kernel::prepareListeners(void)
{
  if(!s_crypt1)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_kernel");

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

	      /*
	      ** We're only interested in creating objects for
	      ** listeners that will listen.
	      */

	      if(query.value(3).toString() == "online")
		{
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
			   id,
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
		}
	      else
		{
		  listener = m_listeners.value(id);

		  if(listener)
		    {
		      listener->close();
		      listener->deleteLater();
		    }

		  m_listeners.remove(id);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_kernel");

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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, remote_port, scope_id, "
		      "status_control, proxy_hostname, proxy_password, "
		      "proxy_port, proxy_type, proxy_username, "
		      "OID FROM neighbors"))
	  while(query.next())
	    {
	      QPointer<spoton_neighbor> neighbor = 0;
	      qint64 id = query.value(9).toLongLong();

	      if(query.value(3).toString() == "connected")
		{
		  if(!m_neighbors.contains(id))
		    {
		      QList<QByteArray> list;

		      for(int i = 0; i < 9; i++)
			if(i == 3) // Status Control
			  continue;
			else
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

		      if(list.size() == 8)
			{
			  QNetworkProxy proxy;

			  /*
			  ** The indices of the list do not correspond
			  ** with the indices of the query container.
			  **
			  ** list[3] - Proxy Hostname
			  ** list[4] - Proxy Password
			  ** list[5] - Proxy Port
			  ** list[6] - Proxy Type
			  ** list[7] - Proxy Username
			  */

			  if(list.at(6) == "HTTP" ||
			     list.at(6) == "Socks5")
			    {
			      proxy.setCapabilities
				(QNetworkProxy::HostNameLookupCapability |
				 QNetworkProxy::TunnelingCapability);
			      proxy.setHostName(list.at(3));
			      proxy.setPassword(list.at(4));
			      proxy.setPort(list.at(5).toUShort());

			      if(list.at(6) == "HTTP")
				proxy.setType(QNetworkProxy::HttpProxy);
			      else
				proxy.setType(QNetworkProxy::Socks5Proxy);

			      proxy.setUser(list.at(7));
			    }
			  else
			    proxy.setType(QNetworkProxy::NoProxy);

			  neighbor = new spoton_neighbor
			    (proxy,
			     list.at(0).constData(),
			     list.at(1).constData(),
			     list.at(2).constData(),
			     id,
			     this);
			}

		      if(neighbor)
			{
			  connectSignalsToNeighbor(neighbor);
			  m_neighbors.insert(id, neighbor);
			}
		    }
		  else
		    neighbor = m_neighbors.value(id);
		}
	      else
		{
		  neighbor = m_neighbors.value(id);

		  if(neighbor)
		    {
		      neighbor->close();
		      neighbor->deleteLater();
		    }

		  m_neighbors.remove(id);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_kernel");

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

void spoton_kernel::slotMessageReceivedFromUI(const qint64 oid,
					      const QByteArray &name,
					      const QByteArray &message)
{
  if(!s_crypt1)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash;

  myPublicKeyHash = spoton_gcrypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QByteArray data;
  QByteArray gemini;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm;
  QString neighborOid("");

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     symmetricKeyAlgorithm,
				     neighborOid,
				     QString::number(oid),
				     s_crypt1);

  data.append
    (spoton_gcrypt::publicKeyEncrypt(symmetricKey,
				     publicKey, &ok).
     toBase64());
  data.append("\n");

  if(ok)
    {
      data.append
	(spoton_gcrypt::publicKeyEncrypt(symmetricKeyAlgorithm,
					 publicKey, &ok).
	 toBase64());
      data.append("\n");
    }

  if(ok)
    {
      spoton_gcrypt crypt(symmetricKeyAlgorithm,
			  QString("sha512"),
			  QByteArray(),
			  symmetricKey,
			  0,
			  0,
			  QString(""));

      data.append
	(crypt.encrypted(myPublicKeyHash, &ok).toBase64());
      data.append("\n");

      if(ok)
	{
	  data.append(crypt.encrypted(name, &ok).toBase64());
	  data.append("\n");
	}

      if(ok)
	{
	  data.append(crypt.encrypted(message, &ok).toBase64());
	  data.append("\n");
	}

      if(ok)
	{
	  QByteArray messageDigest
	    (crypt.keyedHash(symmetricKey +
			     symmetricKeyAlgorithm +
			     myPublicKeyHash +
			     name +
			     message,
			     &ok));

	  if(ok)
	    data.append(crypt.encrypted(messageDigest, &ok).toBase64());
	}

      if(ok)
	if(!gemini.isEmpty())
	  {
	    QByteArray messageDigest;
	    spoton_gcrypt crypt("aes256",
				QString("sha512"),
				QByteArray(),
				gemini,
				0,
				0,
				QString(""));

	    messageDigest = crypt.keyedHash(data, &ok);

	    if(ok)
	      {
		data = crypt.encrypted(data, &ok).toBase64();
		data.append("\n");
	      }

	    if(ok)
	      data.append(crypt.encrypted(messageDigest, &ok).
			  toBase64());
	  }

      if(ok)
	{
	  char c = 0;
	  short ttl = s_settings.value
	    ("kernel/ttl_0000", 16).toInt();

	  memcpy(&c, static_cast<void *> (&ttl), 1);
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

void spoton_kernel::slotPublicKeyReceivedFromUI(const qint64 oid,
						const QByteArray &keyType,
						const QByteArray &name,
						const QByteArray &publicKey,
						const QByteArray &signature,
						const QString &messageType)
{
  if(messageType == "0011")
    {
      QByteArray data
	(spoton_send::message0011(keyType, name, publicKey, signature));

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
  else
    {
      if(m_neighbors.contains(oid))
	m_neighbors[oid]->sharePublicKey
	  (keyType, name, publicKey, signature);
      else
	spoton_misc::logError
	  (QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
		   "neighbor %1 not found in m_neighbors.").arg(oid));
    }
}

void spoton_kernel::slotSettingsChanged(const QString &path)
{
  Q_UNUSED(path);
  s_settings.clear();

  QSettings settings;

  if(!settings.contains("kernel/maximum_number_of_bytes_buffered_by_neighbor"))
    settings.setValue("kernel/maximum_number_of_bytes_buffered_by_neighbor",
		      100000);

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  if(!s_settings.value("gui/scramblerEnabled", false).toBool())
    m_scramblerTimer.stop();
  else
    m_scramblerTimer.start();
}

void spoton_kernel::connectSignalsToNeighbor(spoton_neighbor *neighbor)
{
  if(!neighbor)
    return;

  connect(m_mailer,
	  SIGNAL(sendMailFromPostOffice(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendMailFromPostOffice(const QByteArray &)));
  connect(neighbor,
	  SIGNAL(newEMailArrived(void)),
	  m_guiServer,
	  SLOT(slotNewEMailArrived(void)));
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
	  SIGNAL(receivedMailMessage(const QByteArray &,
				     const qint64)),
	  this,
	  SIGNAL(receivedMailMessage(const QByteArray &,
				     const qint64)));
  connect(neighbor,
	  SIGNAL(receivedStatusMessage(const QByteArray &,
				       const qint64)),
	  this,
	  SIGNAL(receivedStatusMessage(const QByteArray &,
				       const qint64)));
  connect(neighbor,
	  SIGNAL(retrieveMail(const QByteArray &,
			      const QByteArray &,
			      const QByteArray &)),
	  m_mailer,
	  SLOT(slotRetrieveMail(const QByteArray &,
				const QByteArray &,
				const QByteArray &)));
  connect(neighbor,
	  SIGNAL(retrieveMail(const QByteArray &,
			      const qint64)),
	  this,
	  SIGNAL(retrieveMail(const QByteArray &,
			      const qint64)));
  connect(this,
	  SIGNAL(receivedChatMessage(const QByteArray &,
				     const qint64)),
	  neighbor,
	  SLOT(slotReceivedChatMessage(const QByteArray &,
				       const qint64)));
  connect(this,
	  SIGNAL(receivedMailMessage(const QByteArray &,
				     const qint64)),
	  neighbor,
	  SLOT(slotReceivedMailMessage(const QByteArray &,
				       const qint64)));
  connect(this,
	  SIGNAL(receivedStatusMessage(const QByteArray &,
				       const qint64)),
	  neighbor,
	  SLOT(slotReceivedStatusMessage(const QByteArray &,
					 const qint64)));
  connect(this,
	  SIGNAL(retrieveMail(const QByteArray &,
			      const qint64)),
	  neighbor,
	  SLOT(slotRetrieveMail(const QByteArray &,
				const qint64)));
  connect(this,
	  SIGNAL(retrieveMail(const QList<QByteArray> &)),
	  neighbor,
	  SLOT(slotRetrieveMail(const QList<QByteArray> &)));
  connect(this,
	  SIGNAL(sendMail(const QList<QPair<QByteArray, qint64> > &)),
	  neighbor,
	  SLOT(slotSendMail(const QList<QPair<QByteArray, qint64> > &)));
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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("UPDATE friends_public_keys SET "
		      "status = 'offline' WHERE "
		      "neighbor_oid = -1 AND "
		      "strftime('%s', ?) - "
		      "strftime('%s', last_status_update) > ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue
	  (1, 2 * qCeil(m_statusTimer.interval() / 1000.0));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_kernel");

  QByteArray status(s_settings.value("gui/my_status", "Online").
		    toByteArray().toLower());

  if(status == "offline")
    return;

  if(!s_crypt1)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_gcrypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  if(m_guiServer->findChildren<QTcpSocket *> ().isEmpty())
    status = "offline";

  QList<QByteArray> list;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT gemini, public_key "
		      "FROM friends_public_keys WHERE "
		      "neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray data;
	      QByteArray gemini;

	      if(!query.value(0).isNull())
		gemini = s_crypt1->decrypted
		  (QByteArray::fromBase64(query.
					  value(0).
					  toByteArray()),
		   &ok);

	      QByteArray name(s_settings.value("gui/nodeName", "unknown").
			      toByteArray().trimmed());
	      QByteArray publicKey(query.value(1).toByteArray());
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm
		(spoton_gcrypt::randomCipherType());
	      size_t symmetricKeyLength = spoton_gcrypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);

		  /*
		  ** Status messages lack sensitive data.
		  */

		  symmetricKey = spoton_gcrypt::weakRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotStatusTimerExpired(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(symmetricKey,
						     publicKey, &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(symmetricKeyAlgorithm,
						     publicKey, &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  spoton_gcrypt crypt(symmetricKeyAlgorithm,
				      QString("sha512"),
				      QByteArray(),
				      symmetricKey,
				      0,
				      0,
				      QString(""));

		  data.append
		    (crypt.encrypted(myPublicKeyHash, &ok).toBase64());
		  data.append("\n");

		  if(ok)
		    {
		      data.append(crypt.encrypted(name, &ok).toBase64());
		      data.append("\n");
		    }

		  if(ok)
		    {
		      data.append(crypt.encrypted(status, &ok).toBase64());
		      data.append("\n");
		    }

		  if(ok)
		    {
		      QByteArray messageDigest
			(crypt.keyedHash(symmetricKey +
					 symmetricKeyAlgorithm +
					 myPublicKeyHash +
					 name +
					 status,
					 &ok));

		      if(ok)
			data.append
			  (crypt.encrypted(messageDigest, &ok).toBase64());
		    }

		  if(ok)
		    if(!gemini.isEmpty())
		      {
			QByteArray messageDigest;
			spoton_gcrypt crypt("aes256",
					    QString("sha512"),
					    QByteArray(),
					    gemini,
					    0,
					    0,
					    QString(""));

			messageDigest = crypt.keyedHash(data, &ok);

			if(ok)
			  {
			    data = crypt.encrypted(data, &ok).toBase64();
			    data.append("\n");
			  }

			if(ok)
			  data.append(crypt.encrypted(messageDigest, &ok).
				      toBase64());
		      }

		  if(ok)
		    {
		      char c = 0;
		      short ttl = s_settings.value
			("kernel/ttl_0013", 16).toInt();

		      memcpy(&c, static_cast<void *> (&ttl), 1);
		      data.prepend(c);
		      list.append(data);
		    }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_kernel");
  emit sendStatus(list);
}

void spoton_kernel::slotScramble(void)
{
  QByteArray data;
  QByteArray message(qrand() % 1024 + 512, 0);
  QByteArray messageDigest;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm(spoton_gcrypt::randomCipherType());
  bool ok = true;
  size_t symmetricKeyLength = spoton_gcrypt::cipherKeyLength
    (symmetricKeyAlgorithm);

  if(symmetricKeyLength > 0)
    {
      symmetricKey.resize(symmetricKeyLength);
      symmetricKey = spoton_gcrypt::strongRandomBytes
	(symmetricKey.length());
    }
  else
    ok = false;

  if(ok)
    {
      spoton_gcrypt crypt(symmetricKeyAlgorithm,
			  QString("sha512"),
			  QByteArray(),
			  symmetricKey,
			  0,
			  0,
			  QString(""));

      messageDigest = crypt.keyedHash(message, &ok);

      if(ok)
	{
	  data.append(crypt.encrypted(message, &ok).toBase64());
	  data.append("\n");
	}

      if(ok)
	data.append(crypt.encrypted(messageDigest, &ok).toBase64());
    }

  if(ok)
    {
      char c = 0;
      short ttl = s_settings.value
	("kernel/ttl_0000", 16).toInt();

      memcpy(&c, static_cast<void *> (&ttl), 1);
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

  m_scramblerTimer.start(qrand() % 20000 + 40000);
}

void spoton_kernel::slotRetrieveMail(void)
{
  if(!s_crypt1)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_gcrypt::sha512Hash(publicKey, &ok));

  if(!ok)
    return;

  QList<QByteArray> list;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray data;
	      QByteArray publicKey
		(query.value(0).toByteArray());
	      QByteArray signature;
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm
		(spoton_gcrypt::randomCipherType());
	      bool ok = true;
	      size_t symmetricKeyLength = spoton_gcrypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_gcrypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotRetrieveMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      data.append
		(spoton_gcrypt::publicKeyEncrypt(symmetricKey,
						 publicKey,
						 &ok).
		 toBase64());
	      data.append("\n");

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(symmetricKeyAlgorithm,
						     publicKey,
						     &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(myPublicKeyHash,
						     publicKey, &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  QByteArray messageDigest;
		  spoton_gcrypt crypt(symmetricKeyAlgorithm,
				      QString("sha512"),
				      QByteArray(),
				      symmetricKey,
				      0,
				      0,
				      QString(""));

		  messageDigest = crypt.keyedHash
		    (symmetricKey +
		     symmetricKeyAlgorithm +
		     myPublicKeyHash,
		     &ok);

		  if(ok)
		    signature = s_crypt1->digitalSignature
		      (messageDigest, &ok);

		  if(ok)
		    {
		      data.append(crypt.encrypted(signature, &ok).
				  toBase64());
		      data.append("\n");
		    }

		  if(ok)
		    messageDigest = crypt.keyedHash
		      (symmetricKey +
		       symmetricKeyAlgorithm +
		       myPublicKeyHash +
		       signature, &ok);

		  if(ok)
		    data.append(crypt.encrypted(messageDigest, &ok).
				toBase64());
		}

	      if(ok)
		{
		  char c = 0;
		  short ttl = s_settings.value
		    ("kernel/ttl_0002", 16).toInt();

		  memcpy(&c, static_cast<void *> (&ttl), 1);
		  data.prepend(c);
		  list.append(data);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_kernel");
  emit retrieveMail(list);
}

void spoton_kernel::slotSendMail(const QByteArray &goldbug,
				 const QByteArray &message,
				 const QByteArray &name,
				 const QByteArray &publicKey,
				 const QByteArray &subject,
				 const qint64 mailOid)
{
  if(!s_crypt1)
    return;

  /*
  ** goldbug
  ** message
  ** name - my name
  ** publicKey - recipient's public key
  ** subject
  ** mailOid
  */

  QByteArray myPublicKey;
  bool ok = true;

  myPublicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_gcrypt::sha512Hash(myPublicKey, &ok));

  if(!ok)
    return;

  QByteArray recipientHash;

  recipientHash = spoton_gcrypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QList<QPair<QByteArray, qint64> > list;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_kernel");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	/*
	** Use all of our participants as mail carriers.
	*/

	query.setForwardOnly(true);

	if(query.exec("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray data;
	      QByteArray participantPublicKey
		(query.value(0).toByteArray());
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm
		(spoton_gcrypt::randomCipherType());
	      bool ok = true;
	      size_t symmetricKeyLength = spoton_gcrypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_gcrypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      data.append
		(spoton_gcrypt::publicKeyEncrypt(symmetricKey,
						 participantPublicKey,
						 &ok).
		 toBase64());
	      data.append("\n");

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(symmetricKeyAlgorithm,
						     participantPublicKey,
						     &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  spoton_gcrypt crypt(symmetricKeyAlgorithm,
				      QString("sha512"),
				      QByteArray(),
				      symmetricKey,
				      0,
				      0,
				      QString(""));

		  data.append(crypt.encrypted(myPublicKeyHash, &ok).
			      toBase64());
		  data.append("\n");

		  if(ok)
		    {
		      data.append(crypt.encrypted(recipientHash, &ok).
				  toBase64());
		      data.append("\n");
		    }
		}

	      symmetricKeyAlgorithm = spoton_gcrypt::randomCipherType();
	      symmetricKeyLength = spoton_gcrypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_gcrypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(symmetricKey,
						     publicKey,
						     &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(symmetricKeyAlgorithm,
						     publicKey,
						     &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  data.append
		    (spoton_gcrypt::publicKeyEncrypt(myPublicKeyHash,
						     publicKey, &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		{
		  QByteArray messageDigest;
		  spoton_gcrypt *crypt = 0;

		  /*
		  ** If we have a goldbug, encrypt several parts of
		  ** the message with it. The symmetric key that
		  ** we established above will be ignored.
		  */

		  if(goldbug.isEmpty())
		    crypt = new spoton_gcrypt(symmetricKeyAlgorithm,
					      QString("sha512"),
					      QByteArray(),
					      symmetricKey,
					      0,
					      0,
					      QString(""));
		  else
		    crypt = new spoton_gcrypt("aes256",
					      QString("sha512"),
					      QByteArray(),
					      goldbug,
					      0,
					      0,
					      QString(""));

		  data.append(crypt->encrypted(name, &ok).toBase64());
		  data.append("\n");

		  if(ok)
		    {
		      data.append(crypt->encrypted(subject, &ok).toBase64());
		      data.append("\n");
		    }

		  if(ok)
		    {
		      data.append(crypt->encrypted(message, &ok).toBase64());
		      data.append("\n");
		    }

		  if(ok)
		    {
		      if(goldbug.isEmpty())
			messageDigest = crypt->keyedHash
			  (symmetricKey +
			   symmetricKeyAlgorithm +
			   myPublicKeyHash +
			   name +
			   subject +
			   message, &ok);
		      else
			messageDigest = crypt->keyedHash
			  (goldbug +
			   "aes256" +
			   myPublicKeyHash +
			   name +
			   subject +
			   message, &ok);
		    }

		  if(ok)
		    data.append(crypt->encrypted(messageDigest, &ok).
				toBase64());

		  delete crypt;
		}

	      if(ok)
		{
		  char c = 0;
		  short ttl = s_settings.value
		    ("kernel/ttl_0001a", 16).toInt();

		  memcpy(&c, static_cast<void *> (&ttl), 1);
		  data.prepend(c);

		  QPair<QByteArray, qint64> pair
		    (data, mailOid);

		  list.append(pair);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_kernel");
  emit sendMail(list);
}

bool spoton_kernel::initializeSecurityContainers(const QString &passphrase)
{
  if(s_crypt1 && s_crypt2)
    return true;

  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error("");
  bool ok = false;

  salt = QByteArray::fromHex(s_settings.value("gui/salt", "").toByteArray());
  saltedPassphraseHash = s_settings.value("gui/saltedPassphraseHash", "").
    toByteArray();

  if(saltedPassphraseHash ==
     spoton_gcrypt::saltedPassphraseHash(s_settings.value("gui/hashType",
							  "sha512").toString(),
					 passphrase,
					 salt, error).toHex())
    if(error.isEmpty())
      {
	QByteArray key
	  (spoton_gcrypt::derivedKey(s_settings.value("gui/cipherType",
						      "aes256").toString(),
				     s_settings.value("gui/hashType",
						      "sha512").toString(),
				     static_cast
				     <unsigned long> (s_settings.
						      value("gui/"
							    "iterationCount",
							    10000).toInt()),
				     passphrase,
				     salt,
				     error));

	if(error.isEmpty())
	  {
	    ok = true;

	    if(!s_crypt1)
	      {
		s_crypt1 = new spoton_gcrypt
		  (s_settings.value("gui/cipherType",
				    "aes256").toString().trimmed(),
		   s_settings.value("gui/hashType",
				    "sha512").toString().trimmed(),
		   passphrase.toUtf8(),
		   key,
		   s_settings.value("gui/saltLength", 256).toInt(),
		   s_settings.value("gui/iterationCount", 10000).toInt(),
		   "messaging");
		spoton_misc::populateCountryDatabase
		  (spoton_kernel::s_crypt1);
	      }

	    if(!s_crypt2)
	      s_crypt1 = new spoton_gcrypt
		(s_settings.value("gui/cipherType",
				  "aes256").toString().trimmed(),
		 s_settings.value("gui/hashType",
				  "sha512").toString().trimmed(),
		 passphrase.toUtf8(),
		 key,
		 s_settings.value("gui/saltLength", 256).toInt(),
		 s_settings.value("gui/iterationCount", 10000).toInt(),
		 "url");
	  }
      }

  return ok;
}
