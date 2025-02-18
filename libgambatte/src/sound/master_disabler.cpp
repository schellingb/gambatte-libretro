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
#include "master_disabler.h"

MasterDisabler::MasterDisabler(bool &m, uint32_t &s1T, uint32_t &s2T, uint32_t &s3T) :
	master(m),
	slave1Timer(s1T),
	slave2Timer(s2T),
	slave3Timer(s3T)
{}

void MasterDisabler::operator()() {
	master = false;
	slave1Timer = 0xFFFFFFFF;
	slave2Timer = 0xFFFFFFFF;
	slave3Timer = 0xFFFFFFFF;
}
