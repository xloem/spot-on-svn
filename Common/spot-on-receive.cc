/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
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

#include "spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-receive.h"

QList<QByteArray> spoton_receive::process0000
(int length, const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const bool acceptSignedMessagesOnly,
 const QHostAddress &address,
 const quint16 port,
 QByteArray &mc,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    return QList<QByteArray> ();

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));
      bool ok = true;

      if(list.size() == 3)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QPair<QByteArray, QByteArray> gemini;

	  if(symmetricKeys.value(0).isEmpty() ||
	     symmetricKeys.value(2).isEmpty())
	    gemini = spoton_misc::findGeminiInCosmos(list.value(0),
						     list.value(1),
						     s_crypt);
	  else
	    {
	      gemini.first = symmetricKeys.value(0);
	      gemini.second = symmetricKeys.value(2);
	    }

	  if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
	    {
	      QByteArray computedHash;
	      QByteArray message(list.value(0));
	      spoton_crypt crypt("aes256",
				 "sha512",
				 QByteArray(),
				 gemini.first,
				 0,
				 0,
				 QString(""));

	      computedHash = spoton_crypt::keyedHash
		(message, gemini.second, "sha512", &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(1));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      message = crypt.decrypted(message, &ok);

		      if(ok)
			list = message.split('\n');

		      list.removeAt(0); // Message Type

		      if(list.size() != 3)
			{
			  spoton_misc::logError
			    (QString("spoton_receive::process0000(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return QList<QByteArray> ();
			}
		    }
		  else
		    {
		      spoton_misc::logError("spoton_receive::"
					    "process0000(): "
					    "computed message code does "
					    "not match provided code.");
		      return QList<QByteArray> ();
		    }
		}
	    }
	  else
	    return QList<QByteArray> (); /*
					 ** A gemini was not discovered.
					 ** We need to echo.
					 */
	}
      else if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0000(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray keyInformation(list.value(0));
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  list.removeAt(0); // Message Type

	  if(list.size() == 3)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::process0000(): "
			 "received irregular data. "
			 "Expecting 3 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash(data,
						 hashKey,
						 "sha512",
						 &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     "sha512",
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      if(list.size() == 6)
			{
			  for(int i = 0; i < list.size(); i++)
			    list.replace
			      (i, QByteArray::fromBase64(list.at(i)));

			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0), "chat",
						   s_crypt) ||
			     spoton_misc::
			     isAcceptedParticipant(list.value(0), "poptastic",
						   s_crypt))
			    {
			      if(acceptSignedMessagesOnly)
				if(!spoton_misc::
				   isValidSignature(list.value(0) +
						    list.value(1) +
						    list.value(2) +
						    list.value(3) +
						    list.value(4),
						    list.value(0),
						    list.value(5),
						    s_crypt))
				  {
				    spoton_misc::logError
				      ("spoton_receive::"
				       "process0000(): invalid "
				       "signature.");
				    return QList<QByteArray> ();
				  }

			      if(!list.value(0).isEmpty() &&
				 !list.value(1).isEmpty() &&
				 !list.value(2).isEmpty() &&
				 !list.value(3).isEmpty() &&
				 !list.value(4).isEmpty())
				{
				  mc = messageCode;
				  return list;
				}
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_receive::process0000(): "
				   "received irregular data. "
				   "Expecting 6 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_receive::"
				      "process0000(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000(): 0000 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address.toString()).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0000a
(int length, const QByteArray &dataIn,
 const bool acceptSignedMessagesOnly,
 const QHostAddress &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    return QList<QByteArray> ();

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0000a(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray keyInformation(list.value(0));
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  list.removeAt(0); // Message Type

	  if(list.size() == 3)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::process0000a(): "
			 "received irregular data. "
			 "Expecting 3 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash(data, hashKey,
						 "sha512", &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     "sha512",
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      if(list.size() == 5)
			{
			  for(int i = 0; i < list.size(); i++)
			    list.replace
			      (i, QByteArray::fromBase64(list.at(i)));

			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "chat",
						   s_crypt) ||
			     spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "poptastic",
						   s_crypt))
			    {
			      if(acceptSignedMessagesOnly)
				if(!spoton_misc::
				   /*
				   ** 0 - Sender's SHA-512 Hash
				   ** 1 - Gemini Encryption Key
				   ** 2 - Gemini Hash Key
				   ** 3 - Timestamp
				   ** 4 - Signature
				   */

				   isValidSignature(list.value(0) +
						    list.value(1) +
						    list.value(2) +
						    list.value(3),
						    list.value(0),
						    list.value(4),
						    s_crypt))
				  {
				    spoton_misc::logError
				      ("spoton_receive::"
				       "process0000a(): invalid "
				       "signature.");
				    return QList<QByteArray> ();
				  }

			      return list;
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_receive::process0000a(): "
				   "received irregular data. "
				   "Expecting 5 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_receive::process0000a(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000a(): 0000a "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address.toString()).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0000b
(int length, const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const bool acceptSignedMessagesOnly,
 const QHostAddress &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    return QList<QByteArray> ();

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_receivet::process0000b(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** The method findMessageType() verified that the computed
      ** hash is identical to the provided hash during the
      ** discovery of the gemini pair. Other
      ** process() methods perform redundant tests.
      */

      spoton_crypt crypt("aes256",
			 "sha512",
			 QByteArray(),
			 symmetricKeys.value(0),
			 0,
			 0,
			 QString(""));

      data = crypt.decrypted(list.value(0), &ok);

      if(ok)
	{
	  QList<QByteArray> list(data.split('\n'));

	  if(list.size() == 6)
	    {
	      for(int i = 0; i < list.size(); i++)
		list.replace
		  (i, QByteArray::fromBase64(list.at(i)));

	      if(spoton_misc::isAcceptedParticipant(list.value(1),
						    "chat",
						    s_crypt) ||
		 spoton_misc::isAcceptedParticipant(list.value(1),
						    "poptastic",
						    s_crypt))
		{
		  if(acceptSignedMessagesOnly)
		    if(!spoton_misc::
		       /*
		       ** 0 - 0000b
		       ** 1 - Sender's SHA-512 Hash
		       ** 2 - Gemini Encryption Key
		       ** 3 - Gemini Hash Key
		       ** 4 - Timestamp
		       ** 5 - Signature
		       */

		       isValidSignature(list.value(0) +
					list.value(1) +
					list.value(2) +
					list.value(3) +
					list.value(4),
					list.value(1),
					list.value(5),
					s_crypt))
		      {
			spoton_misc::logError
			  ("spoton_receive::"
			   "process0000b(): invalid "
			   "signature.");
			return QList<QByteArray> ();
		      }

		  return list;
		}
	    }
	  else
	    spoton_misc::logError
	      (QString("spoton_receive::process0000b(): "
		       "received irregular data. "
		       "Expecting 6 "
		       "entries, "
		       "received %1.").arg(list.size()));
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000b(): 0000b "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address.toString()).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0013
(int length, const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const bool acceptSignedMessagesOnly,
 const QHostAddress &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    return QList<QByteArray> ();

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));
      bool ok = true;

      if(list.size() == 3)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QPair<QByteArray, QByteArray> gemini;

	  if(symmetricKeys.value(0).isEmpty() ||
	     symmetricKeys.value(2).isEmpty())
	    gemini = spoton_misc::findGeminiInCosmos
	      (list.value(0), list.value(1), s_crypt);
	  else
	    {
	      gemini.first = symmetricKeys.value(0);
	      gemini.second = symmetricKeys.value(2);
	    }

	  if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
	    {
	      QByteArray computedHash;
	      QByteArray message(list.value(0));
	      spoton_crypt crypt("aes256",
				 "sha512",
				 QByteArray(),
				 gemini.first,
				 0,
				 0,
				 QString(""));

	      computedHash = spoton_crypt::keyedHash
		(message, gemini.second, "sha512", &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(1));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      message = crypt.decrypted(message, &ok);

		      if(ok)
			list = message.split('\n');

		      list.removeAt(0); // Message Type

		      if(list.size() != 3)
			{
			  spoton_misc::logError
			    (QString("spoton_receive::process0013(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return QList<QByteArray> ();
			}
		    }
		  else
		    {
		      spoton_misc::logError("spoton_receive::"
					    "process0013(): "
					    "computed message code does "
					    "not match provided code.");
		      return QList<QByteArray> ();
		    }
		}
	    }
	  else
	    return QList<QByteArray> (); /*
					 ** A gemini was not discovered.
					 ** We need to echo.
					 */
	}
      else if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0013(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray keyInformation(list.value(0));
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  list.removeAt(0); // Message Type

	  if(list.size() == 3)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::process0013(): "
			 "received irregular data. "
			 "Expecting 3 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (data, hashKey, "sha512", &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     "sha512",
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      if(list.size() == 5)
			{
			  for(int i = 0; i < list.size(); i++)
			    list.replace
			      (i, QByteArray::fromBase64(list.at(i)));

			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "chat",
						   s_crypt) ||
			     spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "poptastic",
						   s_crypt))
			    {
			      if(acceptSignedMessagesOnly)
				if(!spoton_misc::
				   isValidSignature(list.value(0) +
						    list.value(1) +
						    list.value(2) +
						    list.value(3),
						    list.value(0),
						    list.value(4),
						    s_crypt))
				  {
				    spoton_misc::logError
				      ("spoton_receive::"
				       "process0013(): invalid "
				       "signature.");
				    return QList<QByteArray> ();
				  }

			      return list;
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_receive::process0013(): "
				   "received irregular data. "
				   "Expecting 5 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_receive::process0013(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0013(): 0013 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address.toString()).
       arg(port));

  return QList<QByteArray> ();
}

QString spoton_receive::findMessageType
(const QByteArray &data,
 QList<QByteArray> &symmetricKeys,
 const int interfaces,
 const QHash<QString, spoton_crypt *> &s_crypts,
 const QString &keyType)
{
  QList<QByteArray> list(data.trimmed().split('\n'));
  QString type("");
  spoton_crypt *s_crypt = s_crypts.value(keyType, 0);

  /*
  ** list[0]: Data
  ** ...
  ** list[list.size - 1]: Hash
  ** symmetricKeys[0]: Encryption Key
  ** symmetricKeys[1]: Encryption Type
  ** symmetricKeys[2]: Hash Key
  ** symmetricKeys[3]: Hash Type
  */

  if(s_crypt)
    if(interfaces > 0 &&
       list.size() == 3 && (spoton_misc::
			    participantCount("chat", s_crypt) > 0 ||
			    spoton_misc::
			    participantCount("poptastic", s_crypt) > 0))
      {
	QPair<QByteArray, QByteArray> gemini;

	gemini = spoton_misc::findGeminiInCosmos
	  (QByteArray::fromBase64(list.value(0)),
	   QByteArray::fromBase64(list.value(1)),
	   s_crypt);

	if(!gemini.first.isEmpty())
	  {
	    QByteArray data;
	    bool ok = true;
	    spoton_crypt crypt("aes256",
			       "sha512",
			       QByteArray(),
			       gemini.first,
			       0,
			       0,
			       QString(""));

	    data = crypt.decrypted
	      (QByteArray::fromBase64(list.value(0)), &ok);

	    if(ok)
	      type = QByteArray::fromBase64(data.split('\n').value(0));

	    if(!type.isEmpty())
	      {
		symmetricKeys.append(gemini.first);
		symmetricKeys.append("aes256");
		symmetricKeys.append(gemini.second);
		symmetricKeys.append("sha512");
		goto done_label;
	      }
	    else
	      symmetricKeys.clear();
	  }
	else
	  symmetricKeys.clear();
      }

  if(s_crypt)
    if(interfaces > 0 && list.size() == 4)
      if(!spoton_misc::allParticipantsHaveGeminis())
	if(spoton_misc::participantCount("chat", s_crypt) > 0 ||
	   spoton_misc::participantCount("poptastic", s_crypt) > 0)
	  {
	    QByteArray data;
	    bool ok = true;

	    data = s_crypt->publicKeyDecrypt
	      (QByteArray::fromBase64(list.value(0)), &ok);

	    if(ok)
	      type = QByteArray::fromBase64(data.split('\n').value(0));

	    if(!type.isEmpty())
	      goto done_label;
	  }

 done_label:
  return type;
}
