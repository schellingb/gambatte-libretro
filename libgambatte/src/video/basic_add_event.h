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
#ifndef BASIC_ADD_EVENT_H
#define BASIC_ADD_EVENT_H

#include "ly_counter.h"
#include "video_event_comparer.h"
#include "../event_queue.h"

template<class T>
static inline void addEvent(T &event, const LyCounter &lyCounter, const unsigned cycleCounter, event_queue<VideoEvent*,VideoEventComparer> &queue) {
	if (event.time() == uint32_t(-1)) {
		event.schedule(lyCounter, cycleCounter);
		queue.push(&event);
	}
}

template<class T>
static inline void addEvent(T &event, const unsigned data, const LyCounter &lyCounter, const unsigned cycleCounter, event_queue<VideoEvent*,VideoEventComparer> &queue) {
	if (event.time() == uint32_t(-1)) {
		event.schedule(data, lyCounter, cycleCounter);
		queue.push(&event);
	}
}

#endif
