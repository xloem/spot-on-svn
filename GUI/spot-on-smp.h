/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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

#ifndef _spoton_smp_h_
#define _spoton_smp_h_

#include <QByteArray>
#include <QList>
#include <QString>

extern "C"
{
  /*
  ** Older compilers (GCC 4.2.1) misbehave.
  */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
}

class spoton_smp
{
 public:
  spoton_smp(void);
  ~spoton_smp(void);
  static const unsigned int BITS = 1536;
  QList<QByteArray> step1(bool *ok);
  QList<QByteArray> step2(const QList<QByteArray> &other, bool *ok);
  QList<QByteArray> step3(const QList<QByteArray> &other, bool *ok);
  void setGuess(const QString &guess);

 private:
  gcry_mpi_t m_a2;
  gcry_mpi_t m_a3;
  gcry_mpi_t m_b2;
  gcry_mpi_t m_b3;
  gcry_mpi_t m_generator;
  gcry_mpi_t m_guess;
  gcry_mpi_t m_modulus;
  gcry_mpi_t m_qa;
  gcry_mpi_t m_qb;
  gcry_mpi_t generateRandomExponent(bool *ok);
};

#endif
