/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2006  Damien MATTEI <Damien.MATTEI@free.fr>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 ****************************************************************************/

/* Terminal definitions used to set color of chars, bright and more */

#define RESET		0
#define BRIGHT 		1
#define DIM		2
#define UNDERLINE 	3
#define BLINK		4
#define REVERSE		7
#define HIDDEN		8

#define BLACK 		0
#define RED		1
#define GREEN		2
#define YELLOW		3
#define BLUE		4
#define MAGENTA		5
#define CYAN		6
#define	WHITE		7

/* a color of the 256 colors palette (xterm, VTE, konsole...), with the
 * color of the 8 colors palette used when the terminal lacks it; a layer
 * has two shades: n for its first line, detail for the other lines */
#define COLORSHADES( n , detail , fallback ) (0x1000000 | ((detail) << 16) | ((n) << 8) | (fallback))
#define COLOR256( n , fallback ) COLORSHADES( n , n , fallback )
#define IS_COLOR256( c ) ((c) & 0x1000000)
#define COLOR_MAIN( c ) (((c) >> 8) & 0xff)
#define COLOR_DETAIL( c ) (((c) >> 16) & 0xff)

extern int colors256; /* the terminal knows the 256 colors palette */

extern int use_colors; /* send the colors and attributes (not with -s) */

void LayerSymbol(int); /* show the symbol of the layer shown in a color (-S) */

void SetColor(int); /* set a color, in the shade of the line of its layer */

void OneLineKeep(int); /* with -1, join the next lines of the layer to its first one */
void LayerMain(void); /* the next line is a main line, though in the same layer */

/* escape sequence of the foreground color c: 38;5;n in the palette
 * of 256 colors, 30 + color in the palette of 8 colors */
#define COLORSEQ( c ) ((IS_COLOR256( c ) && colors256) ? "38;5;" : ""), \
  ((IS_COLOR256( c ) && colors256) ? (((c) >> 8) & 0xff) : (((c) & 0xff) + 30))

/* come back in normal mode - reset attributes and color */
#define NORMALMODE()  ((void) (use_colors && printf("%c[0m", 0x1B)))

/* set attribute and color */
#define SETATTCOL( a , c ) ((void) (use_colors && printf("%c[%d;%s%dm", 0x1B, a, COLORSEQ( c ) )))

#define SETATTRIB( a ) ((void) (use_colors && printf("%c[%dm", 0x1B, a )))

#define SETCOLORONLY( c ) SetColor( c )

/* the color of a layer is set before its first line: the place of its
 * symbol (-S), which is shown even without colors */
#define SETCOLOR( c ) (LayerSymbol( c ), SETCOLORONLY( c ))


/* Changes terminal color n ('0' through 'f') to the color
 * represented by the RGB values rr, gg, and bb.
 * (Compatible with Linux console.)
 */
#define SETRGB( n , r , g , b ) printf("%c]P%X%02X%02X%02X", 0x1B, n ,r , g , b )
