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
#ifndef INTERRUPTER_H
#define INTERRUPTER_H

class Memory;

#include <stdint.h>

class Interrupter {
	uint16_t &SP;
	uint16_t &PC;
	bool &halted;
	
public:
	Interrupter(uint16_t &SP, uint16_t &PC, bool &halted);
	unsigned interrupt(const unsigned address, unsigned cycleCounter, Memory &memory);
	
	void unhalt() {
		halted = false;
	}
};

#endif
