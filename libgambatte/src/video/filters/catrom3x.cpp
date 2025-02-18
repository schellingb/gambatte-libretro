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
#include "catrom3x.h"
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

			if (rsum & 0x80000000)
				rsum = 0;
			else if (rsum > 6869)
				rsum = 0xFF0000;
			else {
				rsum *= 607;
				rsum <<= 2;
				rsum += 0x008000;
				rsum &= 0xFF0000;
			}

			if (gsum & 0x80000000)
				gsum = 0;
			else if (gsum > 1758567)
				gsum = 0xFF00;
			else {
				gsum *= 607;
				gsum >>= 14;
				gsum += 0x000080;
				gsum &= 0x00FF00;
			}

			if (bsum & 0x80000000)
				bsum = 0;
			else if (bsum > 6869)
				bsum = 0xFF;
			else {
				bsum *= 607;
				bsum += 8192;
				bsum >>= 14;
			}

			/*rsum/=27;
			rsum<<=8;
			gsum/=27;
			gsum<<=5;
			bsum<<=4;
			bsum+=27;
			bsum/=54;
			rsum+=0x008000;
			gsum+=0x000080;

			if(rsum>0xFF0000) rsum=0xFF0000;
			if(gsum>0x00FF00) gsum=0x00FF00;
			if(bsum>0x0000FF) bsum=0x0000FF;*/

			putPixel(dest++, rsum/*&0xFF0000*/ | gsum/*&0x00FF00*/ | bsum);
		}
		{
			unsigned rsum = sums[1].r * 21;
			unsigned gsum = sums[1].g * 21;
			unsigned bsum = sums[1].b * 21;

			rsum -= sums[0].r << 1;
			gsum -= sums[0].g << 1;
			bsum -= sums[0].b << 1;

			rsum += sums[2].r * 9;
			gsum += sums[2].g * 9;
			bsum += sums[2].b * 9;

			rsum -= sums[3].r;
			gsum -= sums[3].g;
			bsum -= sums[3].b;

			if (rsum & 0x80000000)
				rsum = 0;
			else if (rsum > 185578)
				rsum = 0xFF0000;
			else {
				rsum *= 719;
				rsum >>= 3;
				rsum += 0x008000;
				rsum &= 0xFF0000;
			}

			if (gsum & 0x80000000)
				gsum = 0;
			else if (gsum > 47508223)
				gsum = 0x00FF00;
			else {
				gsum >>= 8;
				gsum *= 719;
				gsum >>= 11;
				gsum += 0x000080;
				gsum &= 0x00FF00;
			}

			if (bsum & 0x80000000)
				bsum = 0;
			else if (bsum > 185578)
				bsum = 0x0000FF;
			else {
				bsum *= 719;
				bsum += 0x040000;
				bsum >>= 19;
			}

			/*rsum/=729;
			rsum<<=8;
			gsum/=729;
			gsum<<=5;
			bsum<<=4;
			bsum+=729;
			bsum/=1458;
			rsum+=0x008000;
			gsum+=0x000080;

			if(rsum>0xFF0000) rsum=0xFF0000;
			if(gsum>0x00FF00) gsum=0x00FF00;
			if(bsum>0x0000FF) bsum=0x0000FF;*/

			putPixel(dest++, rsum/*&0xFF0000*/ | gsum/*&0x00FF00*/ | bsum);
		}
		{
			unsigned rsum = sums[1].r * 9;
			unsigned gsum = sums[1].g * 9;
			unsigned bsum = sums[1].b * 9;

			rsum -= sums[0].r;
			gsum -= sums[0].g;
			bsum -= sums[0].b;

			rsum += sums[2].r * 21;
			gsum += sums[2].g * 21;
			bsum += sums[2].b * 21;

			rsum -= sums[3].r << 1;
			gsum -= sums[3].g << 1;
			bsum -= sums[3].b << 1;

			if (rsum & 0x80000000)
				rsum = 0;
			else if (rsum > 185578)
				rsum = 0xFF0000;
			else {
				rsum *= 719;
				rsum >>= 3;
				rsum += 0x008000;
				rsum &= 0xFF0000;
			}

			if (gsum & 0x80000000)
				gsum = 0;
			else if (gsum > 47508223)
				gsum = 0xFF00;
			else {
				gsum >>= 8;
				gsum *= 719;
				gsum >>= 11;
				gsum += 0x000080;
				gsum &= 0x00FF00;
			}

			if (bsum & 0x80000000)
				bsum = 0;
			else if (bsum > 185578)
				bsum = 0x0000FF;
			else {
				bsum *= 719;
				bsum += 0x040000;
				bsum >>= 19;
			}

			/*rsum/=729;
			rsum<<=8;
			gsum/=729;
			gsum<<=5;
			bsum<<=4;
			bsum+=729;
			bsum/=1458;
			rsum+=0x008000;
			gsum+=0x000080;

			if(rsum>0xFF0000) rsum=0xFF0000;
			if(gsum>0x00FF00) gsum=0x00FF00;
			if(bsum>0x0000FF) bsum=0x0000FF;*/

			putPixel(dest++, rsum/*&0xFF0000*/ | gsum/*&0x00FF00*/ | bsum);
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
				const unsigned pixel = *s;
				sum->r = (pixel >> 16) * 27;
				sum->g = (pixel & 0x00FF00) * 27;
				sum->b = (pixel & 0x0000FF) * 27;

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
				unsigned rsum = (pixel >> 16) * 21;
				unsigned gsum = (pixel & 0x00FF00) * 21;
				unsigned bsum = (pixel & 0x0000FF) * 21;

				pixel = s[-1 * 163];
				rsum -= (pixel >> 16) << 1;
				pixel <<= 1;
				gsum -= pixel & 0x01FE00;
				bsum -= pixel & 0x0001FE;

				pixel = s[1 * 163];
				rsum += (pixel >> 16) * 9;
				gsum += (pixel & 0x00FF00) * 9;
				bsum += (pixel & 0x0000FF) * 9;

				pixel = s[2 * 163];
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

		{
			const uint32_t *s = sline;
			Colorsum *sum = sums;
			unsigned n = 163;
			
			while (n--) {
				unsigned pixel = *s;
				unsigned rsum = (pixel >> 16) * 9;
				unsigned gsum = (pixel & 0x00FF00) * 9;
				unsigned bsum = (pixel & 0x0000FF) * 9;

				pixel = s[-1 * 163];
				rsum -= pixel >> 16;
				gsum -= pixel & 0x00FF00;
				bsum -= pixel & 0x0000FF;

				pixel = s[1 * 163];
				rsum += (pixel >> 16) * 21;
				gsum += (pixel & 0x00FF00) * 21;
				bsum += (pixel & 0x0000FF) * 21;

				pixel = s[2 * 163];
				rsum -= (pixel >> 16) << 1;
				pixel <<= 1;
				gsum -= pixel & 0x01FE00;
				bsum -= pixel & 0x0001FE;

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

Catrom3x::Catrom3x() {
	buffer = NULL;
}

Catrom3x::~Catrom3x() {
	delete []buffer;
}

void Catrom3x::init() {
	delete []buffer;
	
	buffer = new uint32_t[147 * 163];
	std::memset(buffer, 0, 147 * 163 * sizeof(uint32_t));
}

void Catrom3x::outit() {
	delete []buffer;
	buffer = NULL;
}

const FilterInfo& Catrom3x::info() {
	static FilterInfo fInfo = { "Bicubic Catmull-Rom Spline 3x", 160 * 3, 144 * 3 };
	
	return fInfo;
}

uint32_t* Catrom3x::inBuffer() {
	return buffer + 164;
}

unsigned Catrom3x::inPitch() {
	return 163;
}

void Catrom3x::filter(Rgb32Putter::pixel_t *const dbuffer, const unsigned pitch, Rgb32Putter putPixel) {
	::filter(dbuffer, pitch, putPixel, buffer + 163);
}

void Catrom3x::filter(Rgb16Putter::pixel_t *const dbuffer, const unsigned pitch, Rgb16Putter putPixel) {
	::filter(dbuffer, pitch, putPixel, buffer + 163);
}

void Catrom3x::filter(UyvyPutter::pixel_t *const dbuffer, const unsigned pitch, UyvyPutter putPixel) {
	::filter(dbuffer, pitch, putPixel, buffer + 163);
}
