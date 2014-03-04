/*
** Copyright (c) 2011 - 10^10^10 Alexis Megas
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

#include "spot-on.h"

void spoton::slotDiscoverMissingLinks(void)
{
  if(!m_starbeamAnalyzer)
    return;

  QString fileName("");
  QString oid("");
  QString pulseSize("");
  QString totalSize("");
  int row = -1;

  if((row = m_ui.received->currentRow()) >= 0)
    {
      QTableWidgetItem *item = 0;

      item = m_ui.received->item(row, 3); // File

      if(item)
	fileName = item->text();

      item = m_ui.received->item(row, 1); // Pulse Size

      if(item)
	pulseSize = item->text();

      item = m_ui.received->item(row, 2); // Total Size

      if(item)
	totalSize = item->text();

      item = m_ui.received->item
	(row, m_ui.received->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  m_starbeamAnalyzer->add(fileName, oid, pulseSize, totalSize);
  m_starbeamAnalyzer->show(this);
}

void spoton::slotShowStarBeamAnalyzer(void)
{
  if(m_starbeamAnalyzer)
    m_starbeamAnalyzer->show(this);
}

void spoton::slotDemagnetizeMissingLinks(void)
{
}
