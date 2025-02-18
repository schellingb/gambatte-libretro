/***************************************************************************
 *   Copyright (C) 2007 by Sindre Aam�s                                    *
 *   aamas@stud.ntnu.no                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License version 2 as     *
 *   published by the Free Software Foundation.                            *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License version 2 for more details.                *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   version 2 along with this program; if not, write to the               *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/
#include "mode1_irq.h"

Mode1Irq::Mode1Irq(uint8_t &ifReg_in) :
	VideoEvent(0),
	ifReg(ifReg_in)
{
	setDoubleSpeed(false);
	setM1StatIrqEnabled(false);
	reset();
}

void Mode1Irq::doEvent() {
	ifReg |= flags;
	
	setTime(time() + frameTime);
}

void Mode1Irq::schedule(const LyCounter &lyCounter, const unsigned cycleCounter) {
	//setTime(lyCounter.nextFrameCycle(144 * 456 - 1, cycleCounter));
	
	int next = (143 - lyCounter.ly()) * lyCounter.lineTime() + (lyCounter.time() - cycleCounter) - 1;
	if (next <= 0)
		next += frameTime;
	
	setTime(cycleCounter + next);
}
