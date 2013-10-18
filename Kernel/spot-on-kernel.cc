/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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
#include <QDir>
#include <QMutexLocker>
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlRecord>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>
#include <QtCore/qmath.h>

#include <limits>

extern "C"
{
#include "libSpotOn/libspoton.h"
}

extern "C"
{
#include <fcntl.h>
#ifdef Q_OS_WIN32
#include <process.h>
#endif
#include <signal.h>
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_OS2 || \
  defined Q_OS_UNIX
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
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"
#include "spot-on-listener.h"
#include "spot-on-mailer.h"
#include "spot-on-neighbor.h"
#include "spot-on-shared-reader.h"

QHash<QByteArray, QByteArray> spoton_kernel::s_buzzKeys;
QHash<QByteArray, QDateTime> spoton_kernel::s_messagingCache;
QHash<QString, QVariant> spoton_kernel::s_settings;
QHash<QString, spoton_crypt *> spoton_kernel::s_crypts;
QMutex spoton_kernel::s_buzzKeysMutex;
QMutex spoton_kernel::s_messagingCacheMutex;
QMutex spoton_kernel::s_settingsMutex;
static QPointer<spoton_kernel> s_kernel = 0;

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

  if(libspoton_init_b(sharedPath.toStdString().c_str(),
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      &libspotonHandle,
		      65536) == LIBSPOTON_ERROR_NONE) /*
						      ** We don't need
						      ** the stored secure
						      ** memory size here.
						      */
#ifdef Q_OS_WIN32
    libspoton_deregister_kernel(_getpid(), &libspotonHandle);
#else
    libspoton_deregister_kernel(getpid(), &libspotonHandle);
#endif

  libspoton_close(&libspotonHandle);
  QFile::remove(spoton_misc::homePath() + QDir::separator() + "kernel.db");

  /*
  ** _Exit() and _exit() may be safely called from signal handlers.
  */

  _Exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  spoton_crypt::init();

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
  QCoreApplication qapplication(argc, argv);

  QCoreApplication::setApplicationName("Spot-On");
  QCoreApplication::setOrganizationName("Spot-On");
  QCoreApplication::setOrganizationDomain("spot-on.sf.net");
  QCoreApplication::setApplicationVersion(SPOTON_VERSION_STR);
  QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
		     spoton_misc::homePath());
  QSettings::setDefaultFormat(QSettings::IniFormat);

  QSettings settings;

  if(!settings.contains("kernel/gcryctl_init_secmem"))
    settings.setValue("kernel/gcryctl_init_secmem", 65536);

  if(!settings.contains("kernel/tcp_nodelay"))
    settings.setValue("kernel/tcp_nodelay", 1);

  int integer = settings.value("kernel/gcryctl_init_secmem", 65536).toInt();

  if(integer < 65536)
    integer = 65536;

  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;
  libspoton_handle_t libspotonHandle;

  if((err = libspoton_init_b(sharedPath.toStdString().c_str(),
			     0,
			     0,
			     0,
			     0,
			     0,
			     0,
			     0,
			     &libspotonHandle,
			     integer)) == LIBSPOTON_ERROR_NONE)
    err = libspoton_register_kernel(QCoreApplication::applicationPid(),
				    false, // Do not force registration.
				    &libspotonHandle);

  libspoton_close(&libspotonHandle);

  if(err == LIBSPOTON_ERROR_NONE)
    {
      s_kernel = new spoton_kernel();
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
  qsrand(QTime(0, 0, 0).secsTo(QTime::currentTime()));
  QDir().mkdir(spoton_misc::homePath());
  spoton_misc::cleanupDatabases();

  /*
  ** The user interface doesn't yet have a means of preparing advanced
  ** options.
  */

  QSettings settings;

  settings.remove("kernel/ttl_0000");
  settings.remove("kernel/ttl_0001a");
  settings.remove("kernel/ttl_0001b");
  settings.remove("kernel/ttl_0002");
  settings.remove("kernel/ttl_0010");
  settings.remove("kernel/ttl_0013");
  settings.remove("kernel/ttl_0030");
  settings.remove("kernel/ttl_0040a");
  settings.remove("kernel/ttl_0040b");

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  spoton_misc::correctSettingsContainer(s_settings);
  spoton_misc::enableLog
    (setting("gui/kernelLogEvents", false).toBool());

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
	else
	  {
	    qDebug();
	    qDebug() << "Passphrase accepted.";
	  }

	break;
      }

  connect(&m_controlDatabaseTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPollDatabase(void)));
  connect(&m_messagingCachePurgeTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotMessagingCachePurge(void)));
  connect(&m_publishAllListenersPlaintextTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPublicizeAllListenersPlaintext(void)));
  connect(&m_scramblerTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotScramble(void)));
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimerExpired(void)));
  m_controlDatabaseTimer.start(2500);
  m_messagingCachePurgeTimer.setInterval(15000);
  m_publishAllListenersPlaintextTimer.setInterval(10 * 60 * 1000);
  m_scramblerTimer.setSingleShot(true);
  m_statusTimer.start(15000);
  m_guiServer = new spoton_gui_server(this);
  m_mailer = new spoton_mailer(this);
  m_sharedReader = new spoton_shared_reader(this);
  connect(m_guiServer,
	  SIGNAL(buzzReceivedFromUI(const QByteArray &,
				    const QByteArray &,
				    const QByteArray &,
				    const QByteArray &,
				    const QByteArray &,
				    const QByteArray &,
				    const QString &)),
	  this,
	  SLOT(slotBuzzReceivedFromUI(const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QString &)));
  connect(m_guiServer,
	  SIGNAL(callParticipant(const qint64)),
	  this,
	  SLOT(slotCallParticipant(const qint64)));
  connect(m_guiServer,
	  SIGNAL(detachNeighbors(const qint64)),
	  this,
	  SLOT(slotDetachNeighbors(const qint64)));
  connect(m_guiServer,
	  SIGNAL(disconnectNeighbors(const qint64)),
	  this,
	  SLOT(slotDisconnectNeighbors(const qint64)));
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
				    const QByteArray &,
				    const QByteArray &,
				    const QString &)),
     this,
     SLOT(slotPublicKeyReceivedFromUI(const qint64,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QByteArray &,
				      const QString &)));
  connect(m_guiServer,
	  SIGNAL(publicizeAllListenersPlaintext(void)),
	  this,
	  SLOT(slotPublicizeAllListenersPlaintext(void)));
  connect(m_guiServer,
	  SIGNAL(publicizeListenerPlaintext(const qint64)),
	  this,
	  SLOT(slotPublicizeListenerPlaintext(const qint64)));
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

  if(setting("gui/enableCongestionControl", true).toBool())
    {
      s_messagingCache.reserve
	(setting("gui/congestionCost", 10000).toInt());
      m_messagingCachePurgeTimer.start();
    }
}

spoton_kernel::~spoton_kernel()
{
  s_messagingCacheMutex.lock();
  s_messagingCache.clear();
  s_messagingCacheMutex.unlock();
  m_future.waitForFinished();
  cleanup();
  spoton_misc::cleanupDatabases();

  QHashIterator<QString, spoton_crypt *> i(s_crypts);

  while (i.hasNext())
    {
      i.next();
      delete i.value();
    }

  s_crypts.clear();
  spoton_misc::logError(QString("Kernel %1 about to exit.").
			arg(QCoreApplication::applicationPid()));
  QCoreApplication::instance()->quit();
}

void spoton_kernel::cleanup(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_handle_t libspotonHandle;

  if(libspoton_init_b(sharedPath.toStdString().c_str(),
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      &libspotonHandle,
		      setting("kernel/gcryctl_init_secmem", 65536).
		      toInt()) == LIBSPOTON_ERROR_NONE)
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
  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT "
		      "ip_address, "
		      "port, "
		      "scope_id, "
		      "echo_mode, "
		      "status_control, "
		      "maximum_clients, "
		      "ssl_key_size, "
		      "certificate, "
		      "private_key, "
		      "public_key, "
		      "use_accounts, "
		      "OID "
		      "FROM listeners"))
	  while(query.next())
	    {
	      QPointer<spoton_listener> listener = 0;
	      QString status(query.value(4).toString());
	      qint64 id = query.value(11).toLongLong();

	      /*
	      ** We're only interested in creating objects for
	      ** listeners that will listen.
	      */

	      if(status == "deleted")
		{
		  listener = m_listeners.value(id);

		  if(listener)
		    {
		      listener->close();
		      listener->deleteLater();
		    }

		  m_listeners.remove(id);
		  cleanupListenersDatabase(db);
		}
	      else if(status == "offline")
		{
		  listener = m_listeners.value(id);

		  if(listener)
		    listener->close();
		}
	      else if(status == "online")
		{
		  if(!m_listeners.contains(id))
		    {
		      QByteArray certificate;
		      QByteArray privateKey;
		      QByteArray publicKey;
		      QList<QByteArray> list;
		      bool ok = true;

		      for(int i = 0; i < 4; i++)
			{
			  QByteArray bytes;

			  bytes = s_crypt->
			    decrypted(QByteArray::fromBase64(query.
							     value(i).
							     toByteArray()),
				      &ok);

			  if(ok)
			    list.append(bytes);
			  else
			    break;
			}

		      if(ok)
			certificate =
			  s_crypt->decrypted
			  (QByteArray::fromBase64(query.
						  value(7).
						  toByteArray()),
			   &ok);

		      if(ok)
			privateKey =
			  s_crypt->decrypted
			  (QByteArray::fromBase64(query.
						  value(8).
						  toByteArray()),
			   &ok);

		      if(ok)
			publicKey =
			  s_crypt->decrypted
			  (QByteArray::fromBase64(query.
						  value(9).
						  toByteArray()),
			   &ok);

		      if(ok)
			{
			  int maximumClients = query.value(5).toInt();

			  if(!maximumClients)
			    maximumClients = 1;
			  else if(maximumClients !=
				  std::numeric_limits<int>::max())
			    {
			      if(maximumClients % 5 != 0)
				maximumClients = 1;
			    }

			  listener = new spoton_listener
			    (list.value(0).constData(),
			     list.value(1).constData(),
			     list.value(2).constData(),
			     maximumClients,
			     id,
			     list.value(3).constData(),
			     query.value(6).toInt(),
			     certificate,
			     privateKey,
			     publicKey,
			     query.value(10).toInt(),
			     this);
			}

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

		      /*
		      ** Remember, deactivating the listener will not
		      ** destroy it. We need to be able to listen() again.
		      ** We must also be careful if we've never listened
		      ** before because serverAddress() and serverPort()
		      ** will certainly be undefined. Please notice
		      ** that both methods return the values that
		      ** were provided to the listener's constructor.
		      */

		      if(listener)
			if(!listener->isListening())
			  listener->listen(listener->serverAddress(),
					   listener->serverPort());
		    }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QMutableHashIterator<qint64, QPointer<spoton_listener> > it
    (m_listeners);

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	{
	  spoton_misc::logError
	    (QString("spoton_kernel::prepareListeners(): "
		     "listener %1 "
		     " may have been deleted from the listeners table by an"
		     " external event. Purging listener from the listeners "
		     "container.").
	     arg(it.key()));
	  it.remove();
	}
    }
}

void spoton_kernel::prepareNeighbors(void)
{
  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, "
		      "remote_port, "
		      "scope_id, "
		      "status_control, "
		      "proxy_hostname, "
		      "proxy_password, "
		      "proxy_port, "
		      "proxy_type, "
		      "proxy_username, "
		      "user_defined, "
		      "ssl_key_size, "
		      "maximum_buffer_size, "
		      "maximum_content_length, "
		      "echo_mode, "
		      "certificate, "
		      "allow_exceptions, "
		      "protocol, "
		      "ssl_required, "
		      "account_name, "
		      "account_password, "
		      "OID FROM neighbors"))
	  while(query.next())
	    {
	      QPointer<spoton_neighbor> neighbor = 0;
	      qint64 id = query.value(query.record().count() - 1).
		toLongLong();

	      if(query.value(3).toString() == "connected")
		{
		  if(!m_neighbors.contains(id))
		    {
		      QList<QVariant> list;
		      bool userDefined = query.value
			(query.record().indexOf("user_defined")).toBool();

		      for(int i = 0; i < query.record().count() - 1; i++)
			if(i == 3) // status_control
			  list.append("connected");
			else if(i == 9) // user_defined
			  list.append(userDefined);
			else if(i == 10) // ssl_key_size
			  list.append(query.value(i).toInt());
			else if(i == 11 || // maximum_buffer_size
				i == 12)   // maximum_content_length
			  list.append(query.value(i).toInt());
			else if(i == 15) // allow_exceptions
			  list.append(query.value(i).toInt());
			else if(i == 17) // ssl_required
			  list.append(query.value(i).toInt());
			else if(i == 18) // account_name
			  list.append(QByteArray::fromBase64(query.value(i).
							     toByteArray()));
			else if(i == 19) // account_password
			  list.append(QByteArray::fromBase64(query.value(i).
							     toByteArray()));
			else
			  {
			    QByteArray bytes;
			    bool ok = true;

			    bytes = s_crypt->
			      decrypted(QByteArray::fromBase64(query.
							       value(i).
							       toByteArray()),
					&ok);

			    if(ok)
			      list.append(bytes);
			    else
			      break;
			  }

		      if(list.size() == query.record().count() - 1)
			{
			  QNetworkProxy proxy;

			  /*
			  ** The indices of the list do not correspond
			  ** with the indices of the query container.
			  **
			  ** list[4] - Proxy Hostname
			  ** list[5] - Proxy Password
			  ** list[6] - Proxy Port
			  ** list[7] - Proxy Type
			  ** list[8] - Proxy Username
			  */

			  if(list.value(7) == "HTTP" ||
			     list.value(7) == "Socks5")
			    {
			      proxy.setCapabilities
				(QNetworkProxy::HostNameLookupCapability |
				 QNetworkProxy::TunnelingCapability);
			      proxy.setHostName(list.value(4).toByteArray().
						constData());
			      proxy.setPassword(list.value(5).toByteArray().
						constData());
			      proxy.setPort(list.value(6).toByteArray().
					    toUShort()); /*
							 ** toUShort()
							 ** returns zero
							 ** on failure.
							 */

			      if(list.value(7) == "HTTP")
				proxy.setType(QNetworkProxy::HttpProxy);
			      else
				proxy.setType(QNetworkProxy::Socks5Proxy);

			      proxy.setUser(list.value(8).toByteArray().
					    constData());
			    }
			  else if(list.value(7) == "System")
			    {
			      QNetworkProxyQuery proxyQuery;

			      proxyQuery.setQueryType
				(QNetworkProxyQuery::TcpSocket);

			      QList<QNetworkProxy> proxies
				(QNetworkProxyFactory::
				 systemProxyForQuery(proxyQuery));

			      if(!proxies.isEmpty())
				{
				  proxy = proxies.at(0);
				  proxy.setPassword
				    (list.value(5).toByteArray().
				     constData());
				  proxy.setUser(list.value(8).toByteArray().
						constData());
				}
			    }
			  else
			    proxy.setType(QNetworkProxy::NoProxy);

			  neighbor = new spoton_neighbor
			    (proxy,
			     list.value(0).toByteArray().constData(),
			     list.value(1).toByteArray().constData(),
			     list.value(2).toByteArray().constData(),
			     id,
			     userDefined,
			     list.value(10).toInt(),
			     list.value(11).toInt(),
			     list.value(12).toInt(),
			     list.value(13).toByteArray().constData(),
			     list.value(14).toByteArray(),
			     list.value(15).toBool(),
			     list.value(16).toByteArray().constData(),
			     list.value(17).toBool(),
			     list.value(18).toByteArray(),
			     list.value(19).toByteArray(),
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
		      neighbor->abort();
		      neighbor->deleteLater();
		    }

		  m_neighbors.remove(id);
		  cleanupNeighborsDatabase(db);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QMutableHashIterator<qint64, QPointer<spoton_neighbor> > it
    (m_neighbors);
  int disconnected = 0;

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	{
	  spoton_misc::logError
	    (QString("spoton_kernel::prepareNeighbors(): "
		     "neighbor %1 "
		     " may have been deleted from the neighbors table by an"
		     " external event. Purging neighbor from the neighbors "
		     "container.").arg(it.key()));
	  it.remove();
	}
      else if(it.value()->state() == QAbstractSocket::UnconnectedState)
	disconnected += 1;
    }

  if(disconnected == m_neighbors.count())
    {
      s_messagingCacheMutex.lock();
      s_messagingCache.clear();
      s_messagingCacheMutex.unlock();
    }
}

void spoton_kernel::checkForTermination(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  bool registered = false;
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;

  if(QFileInfo(sharedPath).exists())
    {
      libspoton_handle_t libspotonHandle;

      if((err = libspoton_init_b(sharedPath.toStdString().c_str(),
				 0,
				 0,
				 0,
				 0,
				 0,
				 0,
				 0,
				 &libspotonHandle,
				 setting("kernel/gcryctl_init_secmem",
					 65536).toInt())) ==
	 LIBSPOTON_ERROR_NONE)
	registered = QCoreApplication::applicationPid() ==
	  libspoton_registered_kernel_pid(&libspotonHandle, &err);

      libspoton_close(&libspotonHandle);

      if(err == LIBSPOTON_ERROR_SQLITE_DATABASE_LOCKED)
	/*
	** Let's try next time.
	*/

	registered = true;
    }

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
	      neighbor->abort();
	      neighbor->deleteLater();
	    }
	}

      if(err != LIBSPOTON_ERROR_NONE)
	spoton_misc::logError
	  (QString("spoton_kernel::checkForTermination(): "
		   "an error occurred (%1) with libspoton.").
	   arg(err));

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
	  connectSignalsToNeighbor(neighbor);
	  m_neighbors.insert(id, neighbor);
	}
    }
}

void spoton_kernel::slotMessageReceivedFromUI(const qint64 oid,
					      const QByteArray &name,
					      const QByteArray &message)
{
  spoton_crypt *s_crypt1 = s_crypts.value("chat", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value("chat-signature", 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QByteArray cipherType(setting("gui/kernelCipherType",
				"randomized").toString().
			toLatin1());
  QByteArray data;
  QByteArray gemini;
  QByteArray keyInformation;
  QByteArray symmetricKey;
  QString neighborOid("");

  if(cipherType == "randomized")
    cipherType = spoton_crypt::randomCipherType();

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     neighborOid,
				     cipherType,
				     QString::number(oid),
				     s_crypt1);

  keyInformation = spoton_crypt::publicKeyEncrypt
    (QByteArray("0000").toBase64() + "\n" +
     symmetricKey.toBase64() + "\n" +
     cipherType.toBase64(),
     publicKey, &ok);

  if(ok)
    {
      {
	/*
	** We want crypt to be destroyed as soon as possible.
	*/

	QByteArray signature;
	spoton_crypt crypt(cipherType,
			   QString("sha512"),
			   QByteArray(),
			   symmetricKey,
			   0,
			   0,
			   QString(""));

	if(setting("gui/chatSignMessages", true).toBool())
	  signature = s_crypt2->digitalSignature(myPublicKeyHash +
						 name +
						 message, &ok);

	if(ok)
	  data = crypt.encrypted(myPublicKeyHash.toBase64() + "\n" +
				 name.toBase64() + "\n" +
				 message.toBase64() + "\n" +
				 signature.toBase64(), &ok);

	if(ok)
	  {
	    QByteArray messageCode(crypt.keyedHash(data, &ok));

	    if(ok)
	      data = keyInformation.toBase64() +
		"\n" +
		data.toBase64() +
		"\n" +
		messageCode.toBase64();
	  }
      }

      if(ok)
	if(!gemini.isEmpty())
	  {
	    QByteArray messageCode;
	    spoton_crypt crypt("aes256",
			       QString("sha512"),
			       QByteArray(),
			       gemini,
			       0,
			       0,
			       QString(""));

	    data = crypt.encrypted
	      (QByteArray("0000").toBase64() + "\n" + data, &ok);

	    if(ok)
	      messageCode = crypt.keyedHash(data, &ok);

	    if(ok)
	      {
		data = data.toBase64();
		data.append("\n");
		data.append(messageCode.toBase64());
	      }
	  }

      if(ok)
	{
	  if(setting("gui/chatSendMethod",
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
						const QByteArray &sPublicKey,
						const QByteArray &sSignature,
						const QString &messageType)
{
  QPointer<spoton_neighbor> neighbor = 0;

  if(m_neighbors.contains(oid))
    neighbor = m_neighbors[oid];

  if(!neighbor)
    {
      spoton_misc::logError
	  (QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
		   "neighbor %1 not found in m_neighbors.").arg(oid));
      return;
    }

  if(messageType == "0011")
    {
      QByteArray data
	(spoton_send::message0011(keyType, name,
				  publicKey, signature,
				  sPublicKey, sSignature));

      if(neighbor->write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  (QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
		   "write() failure for %1:%2.").
	   arg(neighbor->peerAddress().toString()).
	   arg(neighbor->peerPort()));
      else
	{
	  neighbor->flush();
	  neighbor->addToBytesWritten(data.length());

	  /*
	  ** Now let's update friends_public_keys if the peer also
	  ** shared their key.
	  */

	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "friends_public_keys.db");

	    if(db.open())
	      {
		QSqlQuery query(db);

		query.prepare("UPDATE friends_public_keys SET "
			      "neighbor_oid = -1 "
			      "WHERE neighbor_oid = ? AND "
			      "public_key IS NOT NULL ");
		query.bindValue(0, oid);
		query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }
  else
    neighbor->sharePublicKey
      (keyType, name, publicKey, signature, sPublicKey, sSignature);
}

void spoton_kernel::slotSettingsChanged(const QString &path)
{
  /*
  ** Method may be issued several timer per each change.
  */

  Q_UNUSED(path);
  s_settingsMutex.lock();
  s_settings.clear();

  QSettings settings;

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  spoton_misc::correctSettingsContainer(s_settings);
  s_settingsMutex.unlock();
  spoton_misc::enableLog
    (setting("gui/kernelLogEvents", false).toBool());

  if(!setting("gui/enableCongestionControl", true).toBool())
    {
      m_messagingCachePurgeTimer.stop();
      s_messagingCacheMutex.lock();
      s_messagingCache.clear();
      s_messagingCache.reserve(0);
      s_messagingCacheMutex.unlock();
    }
  else
    {
      int cost = setting("gui/congestionCost", 10000).toInt();

      s_messagingCacheMutex.lock();

      if(s_messagingCache.capacity() != cost)
	s_messagingCache.reserve(cost);

      s_messagingCacheMutex.unlock();

      if(!m_messagingCachePurgeTimer.isActive())
	m_messagingCachePurgeTimer.start();
    }

  if(setting("gui/publishPeriodically", false).toBool())
    {
      if(!m_publishAllListenersPlaintextTimer.isActive())
	m_publishAllListenersPlaintextTimer.start();
    }
  else
    m_publishAllListenersPlaintextTimer.stop();
}

void spoton_kernel::connectSignalsToNeighbor
(QPointer<spoton_neighbor> neighbor)
{
  if(!neighbor)
    return;

  connect(m_mailer,
	  SIGNAL(sendMailFromPostOffice(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendMailFromPostOffice(const QByteArray &)));
  connect(neighbor,
	  SIGNAL(authenticationRequested(const QString &)),
	  m_guiServer,
	  SLOT(slotAuthenticationRequested(const QString &)));
  connect(neighbor,
	  SIGNAL(newEMailArrived(void)),
	  m_guiServer,
	  SLOT(slotNewEMailArrived(void)));
  connect
    (neighbor,
     SIGNAL(receivedBuzzMessage(const QList<QByteArray> &,
				const QPair<QByteArray, QByteArray> &)),
     m_guiServer,
     SLOT(slotReceivedBuzzMessage(const QList<QByteArray> &,
				  const QPair<QByteArray, QByteArray> &)));
  connect(neighbor,
	  SIGNAL(receivedChatMessage(const QByteArray &)),
	  m_guiServer,
	  SLOT(slotReceivedChatMessage(const QByteArray &)));
  connect(neighbor,
	  SIGNAL(scrambleRequest(void)),
	  this,
	  SLOT(slotRequestScramble(void)));
  connect(neighbor,
	  SIGNAL(publicizeListenerPlaintext(const QByteArray &,
					    const qint64)),
	  this,
	  SIGNAL(publicizeListenerPlaintext(const QByteArray &,
					    const qint64)));
  connect(neighbor,
	  SIGNAL(receivedMessage(const QByteArray &,
				 const qint64)),
	  this,
	  SIGNAL(receivedMessage(const QByteArray &,
				 const qint64)));
  connect(neighbor,
	  SIGNAL(retrieveMail(const QByteArray &,
			      const QByteArray &,
			      const QByteArray &)),
	  m_mailer,
	  SLOT(slotRetrieveMail(const QByteArray &,
				const QByteArray &,
				const QByteArray &)));
  connect(this,
	  SIGNAL(callParticipant(const QByteArray &)),
	  neighbor,
	  SLOT(slotCallParticipant(const QByteArray &)));
  connect(this,
	  SIGNAL(publicizeListenerPlaintext(const QByteArray &,
					    const qint64)),
	  neighbor,
	  SLOT(slotPublicizeListenerPlaintext(const QByteArray &,
					      const qint64)));
  connect(this,
	  SIGNAL(publicizeListenerPlaintext(const QHostAddress &,
					    const quint16)),
	  neighbor,
	  SLOT(slotPublicizeListenerPlaintext(const QHostAddress &,
					      const quint16)));
  connect(this,
	  SIGNAL(receivedMessage(const QByteArray &,
				 const qint64)),
	  neighbor,
	  SLOT(slotReceivedMessage(const QByteArray &,
				   const qint64)));
  connect(this,
	  SIGNAL(retrieveMail(const QList<QByteArray> &)),
	  neighbor,
	  SLOT(slotRetrieveMail(const QList<QByteArray> &)));
  connect(this,
	  SIGNAL(sendBuzz(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendBuzz(const QByteArray &)));
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
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys SET "
		      "status = 'offline' WHERE "
		      "neighbor_oid = -1 AND "
		      "strftime('%s', ?) - "
		      "strftime('%s', last_status_update) > ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue
	  (1, 2.5 * qCeil(m_statusTimer.interval() / 1000.0));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QByteArray status(setting("gui/my_status", "Online").
		    toByteArray().toLower());

  if(status == "offline")
    return;

  spoton_crypt *s_crypt1 = s_crypts.value("chat", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value("chat-signature", 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  if(m_guiServer->findChildren<QSslSocket *> ().isEmpty())
    status = "offline";

  QList<QByteArray> list;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT gemini, public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type = 'chat' AND neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray data;
	      QByteArray gemini;
	      bool ok = true;

	      if(!query.isNull(0))
		gemini = s_crypt1->decrypted
		  (QByteArray::fromBase64(query.
					  value(0).
					  toByteArray()),
		   &ok);

	      QByteArray cipherType
		(setting("gui/kernelCipherType",
			 "randomized").toString().toLatin1());

	      if(cipherType == "randomized")
		cipherType = spoton_crypt::randomCipherType();

	      QByteArray keyInformation;
	      QByteArray name(setting("gui/nodeName", "unknown").
			      toByteArray().trimmed());
	      QByteArray publicKey(query.value(1).toByteArray());
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm(cipherType);
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);

		  /*
		  ** Status messages lack sensitive data.
		  */

		  symmetricKey = spoton_crypt::strongRandomBytes
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
		keyInformation = spoton_crypt::publicKeyEncrypt
		  (QByteArray("0013").toBase64() + "\n" +
		   symmetricKey.toBase64() + "\n" +
		   symmetricKeyAlgorithm.toBase64(),
		   publicKey, &ok);

	      if(ok)
		{
		  {
		    /*
		    ** We want crypt to be destroyed as soon as possible.
		    */

		    QByteArray signature;
		    spoton_crypt crypt(symmetricKeyAlgorithm,
				       QString("sha512"),
				       QByteArray(),
				       symmetricKey,
				       0,
				       0,
				       QString(""));

		    if(setting("gui/chatSignMessages", true).toBool())
		      signature = s_crypt2->digitalSignature
			(myPublicKeyHash +
			 name +
			 status, &ok);

		    if(ok)
		      data = crypt.encrypted
			(myPublicKeyHash.toBase64() + "\n" +
			 name.toBase64() + "\n" +
			 status.toBase64() + "\n" +
			 signature.toBase64(), &ok);

		    if(ok)
		      {
			QByteArray messageCode
			  (crypt.keyedHash(data, &ok));

			if(ok)
			  data = keyInformation.toBase64() + "\n" +
			    data.toBase64() + "\n" +
			    messageCode.toBase64();
		      }
		  }

		  if(ok)
		    if(!gemini.isEmpty())
		      {
			QByteArray messageCode;
			spoton_crypt crypt("aes256",
					   QString("sha512"),
					   QByteArray(),
					   gemini,
					   0,
					   0,
					   QString(""));

			data = crypt.encrypted
			  (QByteArray("0013").toBase64() + "\n" + data, &ok);

			if(ok)
			  messageCode = crypt.keyedHash(data, &ok);

			if(ok)
			  {
			    data = data.toBase64();
			    data.append("\n");
			    data.append(messageCode.toBase64());
			  }
		      }

		  if(ok)
		    list.append(data);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  emit sendStatus(list);
}

void spoton_kernel::slotScramble(void)
{
  QByteArray cipherType(setting("gui/kernelCipherType",
				"randomized").toString().
			toLatin1());

  if(cipherType == "randomized")
    cipherType = spoton_crypt::randomCipherType();

  QByteArray data;
  QByteArray message(qrand() % 1024 + 512, 0);
  QByteArray messageCode;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm(cipherType);
  bool ok = true;
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
    (symmetricKeyAlgorithm);

  if(symmetricKeyLength > 0)
    {
      symmetricKey.resize(symmetricKeyLength);
      symmetricKey = spoton_crypt::strongRandomBytes
	(symmetricKey.length());
    }
  else
    ok = false;

  if(ok)
    {
      spoton_crypt crypt(symmetricKeyAlgorithm,
			 QString("sha512"),
			 QByteArray(),
			 symmetricKey,
			 0,
			 0,
			 QString(""));

      data = crypt.encrypted(message, &ok);

      if(ok)
	messageCode = crypt.keyedHash(data, &ok);

      if(ok)
	{
	  data = data.toBase64();
	  data.append("\n");
	  data.append(messageCode.toBase64());
	}
    }

  if(ok)
    {
      if(setting("gui/chatSendMethod",
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

void spoton_kernel::slotRetrieveMail(void)
{
  spoton_crypt *s_crypt = s_crypts.value("email-signature", 0);

  if(!s_crypt)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = s_crypt->publicKey(&ok); /*
				       ** Signature public key.
				       */

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_crypt::sha512Hash(publicKey, &ok));

  if(!ok)
    return;

  QList<QByteArray> list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type = 'email' AND neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray cipherType
		(setting("gui/kernelCipherType",
			 "randomized").toString().toLatin1());

	      if(cipherType == "randomized")
		cipherType = spoton_crypt::randomCipherType();

	      QByteArray data;
	      QByteArray keyInformation;
	      QByteArray message(spoton_crypt::strongRandomBytes(256));
	      QByteArray publicKey
		(query.value(0).toByteArray());
	      QByteArray signature;
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm(cipherType);
	      bool ok = true;
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotRetrieveMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      keyInformation = spoton_crypt::publicKeyEncrypt
		(QByteArray("0002").toBase64() + "\n" +
		 symmetricKey.toBase64() + "\n" +
		 symmetricKeyAlgorithm.toBase64(),
		 publicKey, &ok);

	      if(ok)
		{
		  data.append
		    (spoton_crypt::publicKeyEncrypt(myPublicKeyHash,
						    publicKey, &ok).
		     toBase64());
		  data.append("\n");
		}

	      if(ok)
		signature = s_crypt->digitalSignature(message, &ok);

	      if(ok)
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     QString("sha512"),
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  data = crypt.encrypted(myPublicKeyHash.toBase64() + "\n" +
					 message.toBase64() + "\n" +
					 signature.toBase64(), &ok);

		  if(ok)
		    {
		      QByteArray messageCode(crypt.keyedHash(data, &ok));

		      if(ok)
			data = keyInformation.toBase64() + "\n" +
			  data.toBase64() + "\n" +
			  messageCode.toBase64();
		    }
		}

	      if(ok)
		list.append(data);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  emit retrieveMail(list);
}

void spoton_kernel::slotSendMail(const QByteArray &goldbug,
				 const QByteArray &message,
				 const QByteArray &name,
				 const QByteArray &publicKey,
				 const QByteArray &subject,
				 const qint64 mailOid)
{
  spoton_crypt *s_crypt1 = s_crypts.value("email", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value("email-signature", 0);

  if(!s_crypt2)
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

  QByteArray myPublicKeyHash(spoton_crypt::sha512Hash(myPublicKey, &ok));

  if(!ok)
    return;

  QByteArray recipientHash;

  recipientHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QList<QPair<QByteArray, qint64> > list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

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
		      "key_type = 'email' AND neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray cipherType
		(setting("gui/kernelCipherType",
			 "randomized").toString().toLatin1());

	      if(cipherType == "randomized")
		cipherType = spoton_crypt::randomCipherType();

	      QByteArray data;
	      QByteArray data1;
	      QByteArray data2;
	      QByteArray keyInformation1;
	      QByteArray keyInformation2;
	      QByteArray messageCode;
	      QByteArray participantPublicKey
		(query.value(0).toByteArray());
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm(cipherType);
	      bool ok = true;
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      keyInformation1 = spoton_crypt::publicKeyEncrypt
		(QByteArray("0001a").toBase64() + "\n" +
		 symmetricKey.toBase64() + "\n" +
		 symmetricKeyAlgorithm.toBase64(),
		 participantPublicKey, &ok);

	      if(ok)
		{
		  QByteArray signature;
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     QString("sha512"),
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  if(setting("gui/emailSignMessages",
			     true).toBool())
		    signature = s_crypt2->digitalSignature
		      (myPublicKeyHash + recipientHash, &ok);

		  if(ok)
		    data1 = crypt.encrypted
		      (myPublicKeyHash.toBase64() + "\n" +
		       recipientHash.toBase64() + "\n" +
		       signature.toBase64(), &ok);
		}

	      if(!ok)
		continue;

	      if(setting("gui/kernelCipherType",
			 "randomized").
		 toString() == "randomized")
		symmetricKeyAlgorithm = spoton_crypt::randomCipherType();
	      else
		symmetricKeyAlgorithm = cipherType;

	      symmetricKeyLength = spoton_crypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  symmetricKey.resize(symmetricKeyLength);
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (symmetricKey.length());
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      keyInformation2 = spoton_crypt::publicKeyEncrypt
		/*
		** We need to store the message type 0001b here as
		** the data may be stored in a post office.
		*/

		(QByteArray("0001b").toBase64() + "\n" +
		 symmetricKey.toBase64() + "\n" +
		 symmetricKeyAlgorithm.toBase64(),
		 publicKey, &ok);

	      QList<QByteArray> items;

	      if(ok)
		items << name
		      << subject
		      << message;

	      if(ok)
		if(!goldbug.isEmpty())
		  {
		    spoton_crypt crypt("aes256",
				       QString("sha512"),
				       QByteArray(),
				       goldbug,
				       0,
				       0,
				       QString(""));

		    for(int i = 0; i < items.size(); i++)
		      if(ok)
			items.replace
			  (i, crypt.encrypted(items.at(i), &ok));
		      else
			break;
		  }

	      if(ok)
		{
		  QByteArray signature;
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     QString("sha512"),
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  if(setting("gui/emailSignMessages",
			     true).toBool())
		    signature = s_crypt2->digitalSignature
		      (myPublicKeyHash +
		       items.value(0) +
		       items.value(1) +
		       items.value(2), &ok);

		  if(ok)
		    data2 = crypt.encrypted
		      (myPublicKeyHash.toBase64() + "\n" +
		       items.value(0).toBase64() + "\n" +
		       items.value(1).toBase64() + "\n" +
		       items.value(2).toBase64() + "\n" +
		       signature.toBase64() + "\n" +
		       QVariant(!goldbug.isEmpty()).toByteArray().toBase64(),
		       &ok);

		  if(ok)
		    messageCode = crypt.keyedHash
		      (data2, &ok);
		}

	      if(ok)
		{
		  data = keyInformation1.toBase64() + "\n" +
		    data1.toBase64() + "\n" +
		    keyInformation2.toBase64() + "\n" +
		    data2.toBase64() + "\n" +
		    messageCode.toBase64();

		  QPair<QByteArray, qint64> pair(data, mailOid);

		  list.append(pair);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  emit sendMail(list);
}

bool spoton_kernel::initializeSecurityContainers(const QString &passphrase)
{
  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error("");
  bool ok = false;

  salt = setting("gui/salt", "").toByteArray();
  saltedPassphraseHash = setting("gui/saltedPassphraseHash", "").
    toByteArray();

  if(saltedPassphraseHash ==
     spoton_crypt::saltedPassphraseHash(setting("gui/hashType",
						"sha512").toString(),
					passphrase,
					salt, error))
    if(error.isEmpty())
      {
	QByteArray key
	  (spoton_crypt::derivedKey(setting("gui/cipherType",
					    "aes256").toString(),
				    setting("gui/hashType",
					    "sha512").toString(),
				    setting("gui/""iterationCount",
					    10000).toInt(),
				    passphrase,
				    salt,
				    error));

	if(error.isEmpty())
	  {
	    ok = true;

	    QStringList list;

	    list << "chat"
		 << "chat-signature"
		 << "email"
		 << "email-signature"
		 << "url"
		 << "url-signature";

	    for(int i = 0; i < list.size(); i++)
	      if(!s_crypts.contains(list.at(i)))
		{
		  spoton_crypt *crypt = new spoton_crypt
		    (setting("gui/cipherType",
			     "aes256").toString().trimmed(),
		     setting("gui/hashType",
			     "sha512").toString().trimmed(),
		     QByteArray(),
		     key,
		     setting("gui/saltLength", 256).toInt(),
		     setting("gui/iterationCount", 10000).toInt(),
		     list.at(i));
		  spoton_misc::populateCountryDatabase(crypt);
		  s_crypts.insert(list.at(i), crypt);
		}
	  }
      }

  return ok;
}

void spoton_kernel::cleanupListenersDatabase(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);

  query.exec("DELETE FROM listeners WHERE "
	     "status_control = 'deleted'");
}

void spoton_kernel::cleanupNeighborsDatabase(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);

  query.exec("DELETE FROM neighbors WHERE "
	     "status_control = 'deleted'");
}

void spoton_kernel::slotPublicizeAllListenersPlaintext(void)
{
  QHashIterator<qint64, QPointer<spoton_listener> > i(m_listeners);

  while(i.hasNext())
    {
      i.next();

      QPointer<spoton_listener> listener = i.value();

      if(listener)
	if(!listener->externalAddress().isNull())
	  emit publicizeListenerPlaintext(listener->externalAddress(),
					  listener->externalPort());
    }
}

void spoton_kernel::slotPublicizeListenerPlaintext(const qint64 oid)
{
  QPointer<spoton_listener> listener = m_listeners.value(oid);

  if(listener)
    if(!listener->externalAddress().isNull())
      emit publicizeListenerPlaintext(listener->externalAddress(),
				      listener->externalPort());
}

void spoton_kernel::slotRequestScramble(void)
{
  /*
  ** Send a scrambled message in proximity of a received message.
  */

  if(setting("gui/scramblerEnabled", false).toBool())
    {
      if(!m_scramblerTimer.isActive())
	m_scramblerTimer.start(qrand() % 5000 + 10000);
    }
  else
    m_scramblerTimer.stop();
}

void spoton_kernel::slotBuzzReceivedFromUI(const QByteArray &key,
					   const QByteArray &channelType,
					   const QByteArray &name,
					   const QByteArray &id,
					   const QByteArray &message,
					   const QByteArray &sendMethod,
					   const QString &messageType)
{
  QByteArray data;
  QByteArray messageCode;
  bool ok = true;
  spoton_crypt crypt(channelType,
		     QString("sha512"),
		     QByteArray(),
		     key,
		     0,
		     0,
		     QString(""));

  data.append(messageType.toLatin1().toBase64());
  data.append("\n");

  if(messageType == "0040a")
    {
      data.append(name.toBase64());
      data.append("\n");
      data.append(id.toBase64());
    }
  else
    {
      data.append(name.toBase64());
      data.append("\n");
      data.append(id.toBase64());
      data.append("\n");
      data.append(message.toBase64());
    }

  data = crypt.encrypted(data, &ok);

  if(ok)
    messageCode = crypt.keyedHash(data, &ok);

  if(ok)
    data = data.toBase64() + "\n" + messageCode.toBase64();

  if(ok)
    {
      if(messageType == "0040a")
	emit sendBuzz(spoton_send::message0040a(data));
      else
	{
	  if(sendMethod == "Artificial_GET")
	    emit sendBuzz
	      (spoton_send::message0040b(data,
					 spoton_send::ARTIFICIAL_GET));
	  else
	    emit sendBuzz
	      (spoton_send::message0040b(data,
					 spoton_send::NORMAL_POST));
	}
    }
}

void spoton_kernel::slotMessagingCachePurge(void)
{
  if(m_future.isFinished())
    if(!s_messagingCache.isEmpty())
      m_future = QtConcurrent::run(this, &spoton_kernel::purgeMessagingCache);
}

void spoton_kernel::purgeMessagingCache(void)
{
  if(!s_messagingCacheMutex.tryLock())
    return;

  QDateTime now(QDateTime::currentDateTime());
  QMutableHashIterator<QByteArray, QDateTime> it(s_messagingCache);
  int i = 0;

  while(it.hasNext())
    {
      i += 1;

      if(i >= 100)
	break;

      it.next();

      if(it.value().secsTo(now) > 60)
	it.remove();
    }

  s_messagingCacheMutex.unlock();
}

bool spoton_kernel::messagingCacheContains(const QByteArray &data)
{
  if(!setting("gui/enableCongestionControl", false).toBool())
    return false;

  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return false;

  QByteArray hash;
  bool ok = true;

  hash = s_crypt->keyedHash(data, &ok);

  if(!ok)
    return false;

  QMutexLocker locker(&s_messagingCacheMutex);

  return s_messagingCache.contains(hash);
}

void spoton_kernel::messagingCacheAdd(const QByteArray &data)
{
  if(!setting("gui/enableCongestionControl", false).toBool())
    return;

  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray hash;
  bool ok = true;

  hash = s_crypt->keyedHash(data, &ok);

  if(!ok)
    return;

  s_messagingCacheMutex.lock();

  if(!s_messagingCache.contains(hash))
    s_messagingCache[hash] = QDateTime::currentDateTime();

  s_messagingCacheMutex.unlock();
}

void spoton_kernel::slotDetachNeighbors(const qint64 listenerOid)
{
  QPointer<spoton_listener> listener = 0;

  if(m_listeners.contains(listenerOid))
    listener = m_listeners.value(listenerOid);

  if(listener)
    foreach(spoton_neighbor *socket,
	    listener->findChildren<spoton_neighbor *> ())
      socket->setParent(this);
}

void spoton_kernel::slotDisconnectNeighbors(const qint64 listenerOid)
{
  QPointer<spoton_listener> listener = 0;

  if(m_listeners.contains(listenerOid))
    listener = m_listeners.value(listenerOid);

  if(listener)
    foreach(spoton_neighbor *socket,
	    listener->findChildren<spoton_neighbor *> ())
      {
	socket->flush();
	socket->abort();
	socket->deleteLater();
      }
}

void spoton_kernel::addBuzzKey(const QByteArray &key,
			       const QByteArray &channelType)
{
  if(key.isEmpty() || channelType.isEmpty())
    return;

  s_buzzKeysMutex.lock();
  s_buzzKeys[key] = channelType;
  s_buzzKeysMutex.unlock();
}

void spoton_kernel::removeBuzzKey(const QByteArray &key)
{
  s_buzzKeysMutex.lock();
  s_buzzKeys.remove(key);
  s_buzzKeysMutex.unlock();
}

QPair<QByteArray, QByteArray> spoton_kernel::findBuzzKey
(const QByteArray &data)
{
  s_buzzKeysMutex.lock();

  QHashIterator<QByteArray, QByteArray> it(s_buzzKeys);
  QPair<QByteArray, QByteArray> pair;

  while(it.hasNext())
    {
      it.next();

      bool ok = true;
      spoton_crypt crypt(it.value(),
			 QString("sha512"),
			 QByteArray(),
			 it.key(),
			 0,
			 0,
			 QString(""));

      crypt.decrypted(data, &ok);

      if(ok)
	{
	  pair.first = it.key();
	  pair.second = it.value();
	  break;
	}
    }

  s_buzzKeysMutex.unlock();
  return pair;
}

void spoton_kernel::clearBuzzKeysContainer(void)
{
  s_buzzKeysMutex.lock();
  s_buzzKeys.clear();
  s_buzzKeysMutex.unlock();
}

int spoton_kernel::interfaces(void)
{
  if(s_kernel)
    return s_kernel->m_guiServer->findChildren<QTcpSocket *> ().size();
  else
    return 0;
}

void spoton_kernel::slotCallParticipant(const qint64 oid)
{
  spoton_crypt *s_crypt1 = s_crypts.value("chat", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value("chat-signature", 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QByteArray data;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT gemini, public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type = 'chat' AND neighbor_oid = -1 AND "
		      "OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  if(query.next())
	    {
	      QByteArray gemini;

	      if(!query.isNull(0))
		gemini = s_crypt1->decrypted
		  (QByteArray::fromBase64(query.
					  value(0).
					  toByteArray()),
		   &ok);

	      QByteArray keyInformation;
	      QByteArray publicKey(query.value(1).toByteArray());
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm("aes256");
	      size_t symmetricKeyLength = 0;

	      if(ok)
		{
		  symmetricKeyLength = spoton_crypt::cipherKeyLength
		    (symmetricKeyAlgorithm);

		  if(symmetricKeyLength > 0)
		    {
		      symmetricKey.resize(symmetricKeyLength);
		      symmetricKey = spoton_crypt::strongRandomBytes
			(symmetricKey.length());
		    }
		  else
		    {
		      ok = false;
		      spoton_misc::logError
			("spoton_kernel::slotCallParticipant(): "
			 "cipherKeyLength() failure.");
		    }
		}

	      if(ok)
		keyInformation = spoton_crypt::publicKeyEncrypt
		  (QByteArray("0000a").toBase64() + "\n" +
		   symmetricKey.toBase64() + "\n" +
		   symmetricKeyAlgorithm.toBase64(),
		   publicKey, &ok);

	      if(ok)
		{
		  {
		    /*
		    ** We want crypt to be destroyed as soon as possible.
		    */

		    QByteArray signature;
		    spoton_crypt crypt(symmetricKeyAlgorithm,
				       QString("sha512"),
				       QByteArray(),
				       symmetricKey,
				       0,
				       0,
				       QString(""));

		    if(setting("gui/chatSignMessages", true).toBool())
		      signature = s_crypt2->digitalSignature
			(myPublicKeyHash + gemini, &ok);

		    if(ok)
		      data = crypt.encrypted
			(myPublicKeyHash.toBase64() + "\n" +
			 gemini.toBase64() + "\n" +
			 signature.toBase64(), &ok);

		    if(ok)
		      {
			QByteArray messageCode
			  (crypt.keyedHash(data, &ok));

			if(ok)
			  data = keyInformation.toBase64() + "\n" +
			    data.toBase64() + "\n" +
			    messageCode.toBase64();
		      }
		  }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    emit callParticipant(data);
}

QVariant spoton_kernel::setting(const QString &name,
				const QVariant &defaultValue)
{
  QMutexLocker locker(&s_settingsMutex);

  return s_settings.value(name, defaultValue);
}
