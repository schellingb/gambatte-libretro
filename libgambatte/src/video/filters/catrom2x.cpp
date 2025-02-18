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
#include "catrom2x.h"
#include "filterinfo.h"
#include <cstring>

struct Colorsum {
	uint32_t r, g, b;
};

template<class PixelPutter>
static void merge_columns(typename PixelPutter::pixel_t *dest, const Colorsum *sums, PixelPutter putPixel) {
	unsigned w = 160;
	
	while (w--) {
		{
			unsigned rsum = sums[1].r;
			unsigned gsum = sums[1].g;
			unsigned bsum = sums[1].b;
			
			if (rsum & 0x80000000) rsum = 0;
			if (gsum & 0x80000000) gsum = 0;
			if (bsum & 0x80000000) bsum = 0;
			
			rsum <<= 12;
			rsum += 0x008000;
			gsum >>= 4;
			gsum += 0x0080;
			bsum += 0x0008;
			bsum >>= 4;
			
			if (rsum > 0xFF0000) rsum = 0xFF0000;
			if (gsum > 0x00FF00) gsum = 0x00FF00;
			if (bsum > 0x0000FF) bsum = 0x0000FF;
			
			putPixel(dest++, (rsum & 0xFF0000) | (gsum & 0x00FF00) | bsum);
		}
		
		{
			uint32_t rsum = sums[1].r * 9;
			uint32_t gsum = sums[1].g * 9;
			uint32_t bsum = sums[1].b * 9;
			
			rsum -= sums[0].r;
			gsum -= sums[0].g;
			bsum -= sums[0].b;
			
			rsum += sums[2].r * 9;
			gsum += sums[2].g * 9;
			bsum += sums[2].b * 9;
			
			rsum -= sums[3].r;
			gsum -= sums[3].g;
			bsum -= sums[3].b;
			
			if (rsum & 0x80000000) rsum = 0;
			if (gsum & 0x80000000) gsum = 0;
			if (bsum & 0x80000000) bsum = 0;
			
			rsum <<= 8;
			rsum += 0x008000;
			gsum >>= 8;
			gsum += 0x000080;
			bsum += 0x000080;
			bsum >>= 8;
			
			if (rsum > 0xFF0000) rsum = 0xFF0000;
			if (gsum > 0x00FF00) gsum = 0x00FF00;
			if (bsum > 0x0000FF) bsum = 0x0000FF;
			
			putPixel(dest++, (rsum & 0xFF0000) | (gsum & 0x00FF00) | bsum);
		}
		
		++sums;
	}
}

template<class PixelPutter>
static void filter(typename PixelPutter::pixel_t *dline, const unsigned pitch, PixelPutter putPixel, const uint32_t *sline) {
	Colorsum sums[163];
	
	for (unsigned h = 144; h--;) {
		{
			const uint32_t *s = sline;
			Colorsum *sum = sums;
			unsigned n = 163;
			
			while (n--) {
				unsigned pixel = *s;
				sum->r = (pixel >> 12) & 0x000FF0 ;
				pixel <<= 4;
				sum->g = pixel & 0x0FF000;
				sum->b = pixel & 0x000FF0;
				
				++s;
				++sum;
			}
		}
		
		merge_columns(dline, sums, putPixel);
		dline += pitch;
		
		{
			const uint32_t *s = sline;
			Colorsum *sum = sums;
			unsigned n = 163;
			
			while (n--) {
				unsigned pixel = *s;
				unsigned rsum = (pixel >> 16) * 9;
				unsigned gsum = (pixel & 0x00FF00) * 9;
				unsigned bsum = (pixel & 0x0000FF) * 9;
				
				pixel = s[-1*163];
				rsum -= pixel >> 16;
				gsum -= pixel & 0x00FF00;
				bsum -= pixel & 0x0000FF;
				
				pixel = s[1*163];
				rsum += (pixel >> 16) * 9;
				gsum += (pixel & 0x00FF00) * 9;
				bsum += (pixel & 0x0000FF) * 9;
				
				pixel = s[2*163];
				rsum -= pixel >> 16;
				gsum -= pixel & 0x00FF00;
				bsum -= pixel & 0x0000FF;
				
				sum->r = rsum;
				sum->g = gsum;
				sum->b = bsum;
				
				++s;
				++sum;
			}
		}
		
		merge_columns(dline, sums, putPixel);
		dline += pitch;
		sline += 163;
	}
}

Catrom2x::Catrom2x() {
	buffer = NULL;
}

Catrom2x::~Catrom2x() {
	delete []buffer;
}

void Catrom2x::init() {
	delete []buffer;

	buffer = new uint32_t[147 * 163];
	std::memset(buffer, 0, 147 * 163 * sizeof(uint32_t));
}

void Catrom2x::outit() {
	delete []buffer;
	buffer = NULL;
}

const FilterInfo& Catrom2x::info() {
	static FilterInfo fInfo = { "Bicubic Catmull-Rom Spline 2x", 160 * 2, 144 * 2 };
	
	return fInfo;
}

uint32_t* Catrom2x::inBuffer() {
	return buffer + 164;
}

unsigned Catrom2x::inPitch() {
	return 163;
}

void Catrom2x::filter(Rgb32Putter::pixel_t *const dbuffer, const unsigned pitch, Rgb32Putter putPixel) {
	::filter(dbuffer, pitch, putPixel, buffer + 163);
}

void Catrom2x::filter(Rgb16Putter::pixel_t *const dbuffer, const unsigned pitch, Rgb16Putter putPixel) {
	::filter(dbuffer, pitch, putPixel, buffer + 163);
}

void Catrom2x::filter(UyvyPutter::pixel_t *const dbuffer, const unsigned pitch, UyvyPutter putPixel) {
	::filter(dbuffer, pitch, putPixel, buffer + 163);
}
