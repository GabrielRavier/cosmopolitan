/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/macros.h"
#include "tool/plinko/lib/char.h"

static const unsigned short kWides[][2] = {
    {0x1100, 0x115F},  // HANGUL CHOSEONG KIYEOK..HANGUL CHOSEONG FILLER
    {0x231A, 0x231B},  // WATCH..HOURGLASS
    {0x2329, 0x2329},  // LEFT-POINTING ANGLE BRACKET
    {0x232A, 0x232A},  // RIGHT-POINTING ANGLE BRACKET
    {0x23E9, 0x23EC},  // BLACK RIGHT-POINTING DOUBLE TRIANGLE...
    {0x23F0, 0x23F0},  // ALARM CLOCK
    {0x23F3, 0x23F3},  // HOURGLASS WITH FLOWING SAND
    {0x25FD, 0x25FE},  // WHITE MEDIUM SMALL SQUARE..BLACK MEDIUM SMALL SQUARE
    {0x2614, 0x2615},  // UMBRELLA WITH RAIN DROPS..HOT BEVERAGE
    {0x2648, 0x2653},  // ARIES..PISCES
    {0x267F, 0x267F},  // WHEELCHAIR SYMBOL
    {0x2693, 0x2693},  // ANCHOR
    {0x26A1, 0x26A1},  // HIGH VOLTAGE SIGN
    {0x26AA, 0x26AB},  // MEDIUM WHITE CIRCLE..MEDIUM BLACK CIRCLE
    {0x26BD, 0x26BE},  // SOCCER BALL..BASEBALL
    {0x26C4, 0x26C5},  // SNOWMAN WITHOUT SNOW..SUN BEHIND CLOUD
    {0x26CE, 0x26CE},  // OPHIUCHUS
    {0x26D4, 0x26D4},  // NO ENTRY
    {0x26EA, 0x26EA},  // CHURCH
    {0x26F2, 0x26F3},  // FOUNTAIN..FLAG IN HOLE
    {0x26F5, 0x26F5},  // SAILBOAT
    {0x26FA, 0x26FA},  // TENT
    {0x26FD, 0x26FD},  // FUEL PUMP
    {0x2705, 0x2705},  // WHITE HEAVY CHECK MARK
    {0x270A, 0x270B},  // RaiseD FIST..RaiseD HAND
    {0x2728, 0x2728},  // SPARKLES
    {0x274C, 0x274C},  // CROSS MARK
    {0x274E, 0x274E},  // NEGATIVE SQUARED CROSS MARK
    {0x2753, 0x2755},  // BLACK QUESTION MARK ORNAMENT..WHITE EXCLAMATION MARK
    {0x2757, 0x2757},  // HEAVY EXCLAMATION MARK SYMBOL
    {0x2795, 0x2797},  // HEAVY PLUS SIGN..HEAVY DIVISION SIGN
    {0x27B0, 0x27B0},  // CURLY LOOP
    {0x27BF, 0x27BF},  // DOUBLE CURLY LOOP
    {0x2B1B, 0x2B1C},  // BLACK LARGE SQUARE..WHITE LARGE SQUARE
    {0x2B50, 0x2B50},  // WHITE MEDIUM STAR
    {0x2B55, 0x2B55},  // HEAVY LARGE CIRCLE
    {0x2E80, 0x2E99},  // CJK RADICAL REPEAT..CJK RADICAL RAP
    {0x2E9B, 0x2EF3},  // CJK RADICAL CHOKE..CJK RADICAL C-SIMPLIFIED TURTLE
    {0x2F00, 0x2FD5},  // KANGXI RADICAL ONE..KANGXI RADICAL FLUTE
    {0x2FF0, 0x2FFB},  // IDEOGRAPHIC DESCRIPTION CHARACTER LTR..OVERLAID
    {0x3000, 0x3000},  // IDEOGRAPHIC SPACE
    {0x3001, 0x3003},  // IDEOGRAPHIC COMMA..DITTO MARK
    {0x3004, 0x3004},  // JAPANESE INDUSTRIAL STANDARD SYMBOL
    {0x3005, 0x3005},  // IDEOGRAPHIC ITERATION MARK
    {0x3006, 0x3006},  // IDEOGRAPHIC CLOSING MARK
    {0x3007, 0x3007},  // IDEOGRAPHIC NUMBER ZERO
    {0x3008, 0x3008},  // LEFT ANGLE BRACKET
    {0x3009, 0x3009},  // RIGHT ANGLE BRACKET
    {0x300A, 0x300A},  // LEFT DOUBLE ANGLE BRACKET
    {0x300B, 0x300B},  // RIGHT DOUBLE ANGLE BRACKET
    {0x300C, 0x300C},  // LEFT CORNER BRACKET
    {0x300D, 0x300D},  // RIGHT CORNER BRACKET
    {0x300E, 0x300E},  // LEFT WHITE CORNER BRACKET
    {0x300F, 0x300F},  // RIGHT WHITE CORNER BRACKET
    {0x3010, 0x3010},  // LEFT BLACK LENTICULAR BRACKET
    {0x3011, 0x3011},  // RIGHT BLACK LENTICULAR BRACKET
    {0x3012, 0x3013},  // POSTAL MARK..GETA MARK
    {0x3014, 0x3014},  // LEFT TORTOISE SHELL BRACKET
    {0x3015, 0x3015},  // RIGHT TORTOISE SHELL BRACKET
    {0x3016, 0x3016},  // LEFT WHITE LENTICULAR BRACKET
    {0x3017, 0x3017},  // RIGHT WHITE LENTICULAR BRACKET
    {0x3018, 0x3018},  // LEFT WHITE TORTOISE SHELL BRACKET
    {0x3019, 0x3019},  // RIGHT WHITE TORTOISE SHELL BRACKET
    {0x301A, 0x301A},  // LEFT WHITE SQUARE BRACKET
    {0x301B, 0x301B},  // RIGHT WHITE SQUARE BRACKET
    {0x301C, 0x301C},  // WAVE DASH
    {0x301D, 0x301D},  // REVERSED DOUBLE PRIME QUOTATION MARK
    {0x301E, 0x301F},  // DOUBLE PRIME QUOTATION MARK..LOW DOUBLE PRIME
    {0x3020, 0x3020},  // POSTAL MARK FACE
    {0x3021, 0x3029},  // HANGZHOU NUMERAL ONE..HANGZHOU NUMERAL NINE
    {0x302A, 0x302D},  // IDEOGRAPHIC LEVEL TONE MARK..ENTERING TONE MARK
    {0x302E, 0x302F},  // HANGUL SINGLE DOT TONE MARK..DOUBLE DOT TONE MARK
    {0x3030, 0x3030},  // WAVY DASH
    {0x3031, 0x3035},  // VERTICAL KANA REPEAT MARK..KANA REPEAT MARK LOWER
    {0x3036, 0x3037},  // CIRCLED POSTAL MARK..IDEOGRAPHIC TELEGRAPH LF SYMBOL
    {0x3038, 0x303A},  // HANGZHOU NUMERAL TEN..HANGZHOU NUMERAL THIRTY
    {0x303B, 0x303B},  // VERTICAL IDEOGRAPHIC ITERATION MARK
    {0x303C, 0x303C},  // MASU MARK
    {0x303D, 0x303D},  // PART ALTERNATION MARK
    {0x303E, 0x303E},  // IDEOGRAPHIC VARIATION INDICATOR
    {0x3041, 0x3096},  // HIRAGANA LETTER SMALL A..HIRAGANA LETTER SMALL KE
    {0x3099, 0x309A},  // COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK...
    {0x309B, 0x309C},  // KATAKANA-HIRAGANA VOICED SOUND MARK...
    {0x309D, 0x309E},  // HIRAGANA ITERATION MARK..VOICED ITERATION MARK
    {0x309F, 0x309F},  // HIRAGANA DIGRAPH YORI
    {0x30A0, 0x30A0},  // KATAKANA-HIRAGANA DOUBLE HYPHEN
    {0x30A1, 0x30FA},  // KATAKANA LETTER SMALL A..KATAKANA LETTER VO
    {0x30FB, 0x30FB},  // KATAKANA MIDDLE DOT
    {0x30FC, 0x30FE},  // KATAKANA-HIRAGANA PROLONGED SOUND MARK..ITERATION
    {0x30FF, 0x30FF},  // KATAKANA DIGRAPH KOTO
    {0x3105, 0x312F},  // BOPOMOFO LETTER B..BOPOMOFO LETTER NN
    {0x3131, 0x318E},  // HANGUL LETTER KIYEOK..HANGUL LETTER ARAEAE
    {0x3190, 0x3191},  // IDEOGRAPHIC ANNOTATION LINKING MARK..REVERSE
    {0x3192, 0x3195},  // IDEOGRAPHIC ANNOTATION ONE MARK..FOUR
    {0x3196, 0x319F},  // IDEOGRAPHIC ANNOTATION TOP MARK..MAN
    {0x31A0, 0x31BF},  // BOPOMOFO LETTER BU..BOPOMOFO LETTER AH
    {0x31C0, 0x31E3},  // CJK STROKE T..CJK STROKE Q
    {0x31F0, 0x31FF},  // KATAKANA LETTER SMALL KU..KATAKANA LETTER SMALL RO
    {0x3200, 0x321E},  // PARENTHESIZED HANGUL KIYEOK..CHARACTER O HU
    {0x3220, 0x3229},  // PARENTHESIZED IDEOGRAPH ONE..TEN
    {0x322A, 0x3247},  // PARENTHESIZED IDEOGRAPH MOON..CIRCLED IDEOGRAPH KOTO
    {0x3250, 0x3250},  // PARTNERSHIP SIGN
    {0x3251, 0x325F},  // CIRCLED NUMBER TWENTY ONE..CIRCLED 35
    {0x3260, 0x327F},  // CIRCLED HANGUL KIYEOK..KOREAN STANDARD SYMBOL
    {0x3280, 0x3289},  // CIRCLED IDEOGRAPH ONE..CIRCLED IDEOGRAPH TEN
    {0x328A, 0x32B0},  // CIRCLED IDEOGRAPH MOON..CIRCLED IDEOGRAPH NIGHT
    {0x32B1, 0x32BF},  // CIRCLED NUMBER THIRTY SIX..CIRCLED NUMBER FIFTY
    {0x32C0, 0x32FF},  // TELEGRAPH SYMBOL FOR JANUARY..SQUARE ERA NAME REIWA
    {0x3300, 0x33FF},  // SQUARE APAATO..SQUARE GAL
    {0x3400, 0x4DBF},  // CJK UNIFIED IDEOGRAPH
    {0x4E00, 0x9FFF},  // CJK UNIFIED IDEOGRAPH
    {0xA000, 0xA014},  // YI SYLLABLE IT..YI SYLLABLE E
    {0xA015, 0xA015},  // YI SYLLABLE WU
    {0xA016, 0xA48C},  // YI SYLLABLE BIT..YI SYLLABLE YYR
    {0xA490, 0xA4C6},  // YI RADICAL QOT..YI RADICAL KE
    {0xA960, 0xA97C},  // HANGUL CHOSEONG TIKEUT-MIEUM..SSANGYEORINHIEUH
    {0xAC00, 0xD7A3},  // HANGUL SYLLABLE GA..HANGUL SYLLABLE HIH
    {0xF900, 0xFA6D},  // CJK COMPATIBILITY IDEOGRAPH
    {0xFA6E, 0xFA6F},  // RESERVED
    {0xFA70, 0xFAD9},  // CJK COMPATIBILITY IDEOGRAPH
    {0xFADA, 0xFAFF},  // RESERVED
    {0xFE10, 0xFE16},  // PRESENTATION FORM FOR VERTICAL COMMA..QUESTION
    {0xFE17, 0xFE17},  // VERTICAL LEFT WHITE LENTICULAR BRACKET
    {0xFE18, 0xFE18},  // VERTICAL RIGHT WHITE LENTICULAR BRAKCET
    {0xFE19, 0xFE19},  // PRESENTATION FORM FOR VERTICAL HORIZONTAL ELLIPSIS
    {0xFE30, 0xFE30},  // PRESENTATION FORM FOR VERTICAL TWO DOT LEADER
    {0xFE31, 0xFE32},  // VERTICAL EM DASH..VERTICAL EN DASH
    {0xFE33, 0xFE34},  // VERTICAL LOW LINE..VERTICAL WAVY LOW LINE
    {0xFE35, 0xFE35},  // PRESENTATION FORM FOR VERTICAL LEFT PARENTHESIS
    {0xFE36, 0xFE36},  // PRESENTATION FORM FOR VERTICAL RIGHT PARENTHESIS
    {0xFE37, 0xFE37},  // PRESENTATION FORM FOR VERTICAL LEFT CURLY BRACKET
    {0xFE38, 0xFE38},  // PRESENTATION FORM FOR VERTICAL RIGHT CURLY BRACKET
    {0xFE39, 0xFE39},  // VERTICAL LEFT TORTOISE SHELL BRACKET
    {0xFE3A, 0xFE3A},  // VERTICAL RIGHT TORTOISE SHELL BRACKET
    {0xFE3B, 0xFE3B},  // VERTICAL LEFT BLACK LENTICULAR BRACKET
    {0xFE3C, 0xFE3C},  // VERTICAL RIGHT BLACK LENTICULAR BRACKET
    {0xFE3D, 0xFE3D},  // VERTICAL LEFT DOUBLE ANGLE BRACKET
    {0xFE3E, 0xFE3E},  // VERTICAL RIGHT DOUBLE ANGLE BRACKET
    {0xFE3F, 0xFE3F},  // VERTICAL LEFT ANGLE BRACKET
    {0xFE40, 0xFE40},  // VERTICAL RIGHT ANGLE BRACKET
    {0xFE41, 0xFE41},  // VERTICAL LEFT CORNER BRACKET
    {0xFE42, 0xFE42},  // VERTICAL RIGHT CORNER BRACKET
    {0xFE43, 0xFE43},  // VERTICAL LEFT WHITE CORNER BRACKET
    {0xFE44, 0xFE44},  // VERTICAL RIGHT WHITE CORNER BRACKET
    {0xFE45, 0xFE46},  // SESAME DOT..WHITE SESAME DOT
    {0xFE47, 0xFE47},  // VERTICAL LEFT SQUARE BRACKET
    {0xFE48, 0xFE48},  // VERTICAL RIGHT SQUARE BRACKET
    {0xFE49, 0xFE4C},  // DASHED OVERLINE..DOUBLE WAVY OVERLINE
    {0xFE4D, 0xFE4F},  // DASHED LOW LINE..WAVY LOW LINE
    {0xFE50, 0xFE52},  // SMALL COMMA..SMALL FULL STOP
    {0xFE54, 0xFE57},  // SMALL SEMICOLON..SMALL EXCLAMATION MARK
    {0xFE58, 0xFE58},  // SMALL EM DASH
    {0xFE59, 0xFE59},  // SMALL LEFT PARENTHESIS
    {0xFE5A, 0xFE5A},  // SMALL RIGHT PARENTHESIS
    {0xFE5B, 0xFE5B},  // SMALL LEFT CURLY BRACKET
    {0xFE5C, 0xFE5C},  // SMALL RIGHT CURLY BRACKET
    {0xFE5D, 0xFE5D},  // SMALL LEFT TORTOISE SHELL BRACKET
    {0xFE5E, 0xFE5E},  // SMALL RIGHT TORTOISE SHELL BRACKET
    {0xFE5F, 0xFE61},  // SMALL NUMBER SIGN..SMALL ASTERISK
    {0xFE62, 0xFE62},  // SMALL PLUS SIGN
    {0xFE63, 0xFE63},  // SMALL HYPHEN-MINUS
    {0xFE64, 0xFE66},  // SMALL LESS-THAN SIGN..SMALL EQUALS SIGN
    {0xFE68, 0xFE68},  // SMALL REVERSE SOLIDUS
    {0xFE69, 0xFE69},  // SMALL DOLLAR SIGN
    {0xFE6A, 0xFE6B},  // SMALL PERCENT SIGN..SMALL COMMERCIAL AT
    {0xFF01, 0xFF03},  // EXCLAMATION MARK..NUMBER SIGN
    {0xFF04, 0xFF04},  // DOLLAR SIGN
    {0xFF05, 0xFF07},  // PERCENT SIGN..APOSTROPHE
    {0xFF08, 0xFF08},  // LEFT PARENTHESIS
    {0xFF09, 0xFF09},  // RIGHT PARENTHESIS
    {0xFF0A, 0xFF0A},  // ASTERISK
    {0xFF0B, 0xFF0B},  // PLUS SIGN
    {0xFF0C, 0xFF0C},  // COMMA
    {0xFF0D, 0xFF0D},  // HYPHEN-MINUS
    {0xFF0E, 0xFF0F},  // FULL STOP..SOLIDUS
    {0xFF10, 0xFF19},  // DIGIT ZERO..DIGIT NINE
    {0xFF1A, 0xFF1B},  // COLON..SEMICOLON
    {0xFF1C, 0xFF1E},  // LESS-THAN..GREATER-THAN
    {0xFF1F, 0xFF20},  // QUESTION MARK..COMMERCIAL AT
    {0xFF21, 0xFF3A},  // LATIN CAPITAL LETTER A..Z
    {0xFF3B, 0xFF3B},  // LEFT SQUARE BRACKET
    {0xFF3C, 0xFF3C},  // REVERSE SOLIDUS
    {0xFF3D, 0xFF3D},  // RIGHT SQUARE BRACKET
    {0xFF3E, 0xFF3E},  // CIRCUMFLEX ACCENT
    {0xFF3F, 0xFF3F},  // LOW LINE
    {0xFF40, 0xFF40},  // GRAVE ACCENT
    {0xFF41, 0xFF5A},  // LATIN SMALL LETTER A..Z
    {0xFF5B, 0xFF5B},  // LEFT CURLY BRACKET
    {0xFF5C, 0xFF5C},  // VERTICAL LINE
    {0xFF5D, 0xFF5D},  // RIGHT CURLY BRACKET
    {0xFF5E, 0xFF5E},  // TILDE
    {0xFF5F, 0xFF5F},  // LEFT WHITE PARENTHESIS
    {0xFF60, 0xFF60},  // RIGHT WHITE PARENTHESIS
    {0xFFE0, 0xFFE1},  // CENT SIGN..POUND SIGN
    {0xFFE2, 0xFFE2},  // NOT SIGN
    {0xFFE3, 0xFFE3},  // MACRON
    {0xFFE4, 0xFFE4},  // BROKEN BAR
    {0xFFE5, 0xFFE6},  // YEN SIGN..WON SIGN
};

static const int kAstralWides[][2] = {
    {0x16FE0, 0x16FE1},  // TANGUT ITERATION MARK..NUSHU ITERATION MARK
    {0x16FE2, 0x16FE2},  // OLD CHINESE HOOK MARK
    {0x16FE3, 0x16FE3},  // OLD CHINESE ITERATION MARK
    {0x16FE4, 0x16FE4},  // KHITAN SMALL SCRIPT FILLER
    {0x16FF0, 0x16FF1},  // VIETNAMESE ALTERNATE READING MARK CA..NHAY
    {0x17000, 0x187F7},  // TANGUT IDEOGRAPH
    {0x18800, 0x18AFF},  // TANGUT COMPONENT
    {0x18B00, 0x18CD5},  // KHITAN SMALL SCRIPT CHARACTER
    {0x18D00, 0x18D08},  // TANGUT IDEOGRAPH
    {0x1AFF0, 0x1AFF3},  // KATAKANA LETTER MINNAN TONE-2..5
    {0x1AFF5, 0x1AFFB},  // KATAKANA LETTER MINNAN TONE-7..5
    {0x1AFFD, 0x1AFFE},  // KATAKANA LETTER MINNAN NASALIZED TONE-7..8
    {0x1B000, 0x1B0FF},  // KATAKANA LETTER ARCHAIC E..HENTAIGANA LETTER RE-2
    {0x1B100, 0x1B122},  // HENTAIGANA LETTER RE-3..KATAKANA LETTER ARCHAIC WU
    {0x1B150, 0x1B152},  // HIRAGANA LETTER SMALL WI..HIRAGANA LETTER SMALL WO
    {0x1B164, 0x1B167},  // KATAKANA LETTER SMALL WI..KATAKANA LETTER SMALL N
    {0x1B170, 0x1B2FB},  // NUSHU CHARACTER-1B170..NUSHU CHARACTER-1B2FB
    {0x1F004, 0x1F004},  // MAHJONG TILE RED DRAGON
    {0x1F0CF, 0x1F0CF},  // PLAYING CARD BLACK JOKER
    {0x1F18E, 0x1F18E},  // NEGATIVE SQUARED AB
    {0x1F191, 0x1F19A},  // SQUARED CL..SQUARED VS
    {0x1F200, 0x1F202},  // SQUARE HIRAGANA HOKA..SQUARED KATAKANA SA
    {0x1F210, 0x1F23B},  // SQUARED CJK UNIFIED IDEOGRAPH
    {0x1F240, 0x1F248},  // TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH
    {0x1F250, 0x1F251},  // CIRCLED IDEOGRAPH ADVANTAGE..ACCEPT
    {0x1F260, 0x1F265},  // ROUNDED SYMBOL FOR FU..ROUNDED SYMBOL FOR CAI
    {0x1F300, 0x1F320},  // CYCLONE..SHOOTING STAR
    {0x1F32D, 0x1F335},  // HOT DOG..CACTUS
    {0x1F337, 0x1F37C},  // TULIP..BABY BOTTLE
    {0x1F37E, 0x1F393},  // BOTTLE WITH POPPING CORK..GRADUATION CAP
    {0x1F3A0, 0x1F3CA},  // CAROUSEL HORSE..SWIMMER
    {0x1F3CF, 0x1F3D3},  // CRICKET BAT AND BALL..TABLE TENNIS PADDLE AND BALL
    {0x1F3E0, 0x1F3F0},  // HOUSE BUILDING..EUROPEAN CASTLE
    {0x1F3F4, 0x1F3F4},  // WAVING BLACK FLAG
    {0x1F3F8, 0x1F3FA},  // BADMINTON RACQUET AND SHUTTLECOCK..AMPHORA
    {0x1F3FB, 0x1F3FF},  // EMOJI MODIFIER FITZPATRICK TYPE-1-2..6
    {0x1F400, 0x1F43E},  // RAT..PAW PRINTS
    {0x1F440, 0x1F440},  // EYES
    {0x1F442, 0x1F4FC},  // EAR..VIDEOCASSETTE
    {0x1F4FF, 0x1F53D},  // PRAYER BEADS..DOWN-POINTING SMALL RED TRIANGLE
    {0x1F54B, 0x1F54E},  // KAABA..MENORAH WITH NINE BRANCHES
    {0x1F550, 0x1F567},  // CLOCK FACE ONE OCLOCK..CLOCK FACE TWELVE-THIRTY
    {0x1F57A, 0x1F57A},  // MAN DANCING
    {0x1F595, 0x1F596},  // REVERSED HAND WITH MIDDLE FINGER EXTENDED..FINGERS
    {0x1F5A4, 0x1F5A4},  // BLACK HEART
    {0x1F5FB, 0x1F5FF},  // MOUNT FUJI..MOYAI
    {0x1F600, 0x1F64F},  // GRINNING FACE..PERSON WITH FOLDED HANDS
    {0x1F680, 0x1F6C5},  // ROCKET..LEFT LUGGAGE
    {0x1F6CC, 0x1F6CC},  // SLEEPING ACCOMMODATION
    {0x1F6D0, 0x1F6D2},  // PLACE OF WORSHIP..SHOPPING TROLLEY
    {0x1F6D5, 0x1F6D7},  // HINDU TEMPLE..ELEVATOR
    {0x1F6DD, 0x1F6DF},  // PLAYGROUND SLIDE..RING BUOY
    {0x1F6EB, 0x1F6EC},  // AIRPLANE DEPARTURE..AIRPLANE ARRIVING
    {0x1F6F4, 0x1F6FC},  // SCOOTER..ROLLER SKATE
    {0x1F7E0, 0x1F7EB},  // LARGE ORANGE CIRCLE..LARGE BROWN SQUARE
    {0x1F7F0, 0x1F7F0},  // HEAVY EQUALS SIGN
    {0x1F90C, 0x1F93A},  // PINCHED FINGERS..FENCER
    {0x1F93C, 0x1F945},  // WRESTLERS..GOAL NET
    {0x1F947, 0x1F9FF},  // FIRST PLACE MEDAL..NAZAR AMULET
    {0x1FA70, 0x1FA74},  // BALLET SHOES..THONG SANDAL
    {0x1FA78, 0x1FA7C},  // DROP OF BLOOD..CRUTCH
    {0x1FA80, 0x1FA86},  // YO-YO..NESTING DOLLS
    {0x1FA90, 0x1FAAC},  // RINGED PLANET..HAMSA
    {0x1FAB0, 0x1FABA},  // FLY..NEST WITH EGGS
    {0x1FAC0, 0x1FAC5},  // ANATOMICAL HEART..PERSON WITH CROWN
    {0x1FAD0, 0x1FAD9},  // BLUEBERRIES..JAR
    {0x1FAE0, 0x1FAE7},  // MELTING FACE..BUBBLES
    {0x1FAF0, 0x1FAF6},  // HAND WITH INDEX FINGER THUMB CROSSED..HEART HANDS
    {0x20000, 0x2A6DF},  // CJK UNIFIED IDEOGRAPH
    {0x2A6E0, 0x2A6FF},  // RESERVED
    {0x2A700, 0x2B738},  // CJK UNIFIED IDEOGRAPH
    {0x2B739, 0x2B73F},  // RESERVED
    {0x2B740, 0x2B81D},  // CJK UNIFIED IDEOGRAPH
    {0x2B81E, 0x2B81F},  // RESERVED
    {0x2B820, 0x2CEA1},  // CJK UNIFIED IDEOGRAPH
    {0x2CEA2, 0x2CEAF},  // RESERVED
    {0x2CEB0, 0x2EBE0},  // CJK UNIFIED IDEOGRAPH
    {0x2EBE1, 0x2F7FF},  // RESERVED
    {0x2F800, 0x2FA1D},  // CJK COMPATIBILITY IDEOGRAPH
    {0x2FA1E, 0x2FA1F},  // RESERVED
    {0x2FA20, 0x2FFFD},  // RESERVED
    {0x30000, 0x3134A},  // CJK UNIFIED IDEOGRAPH
    {0x3134B, 0x3FFFD},  // RESERVED
};

pureconst bool IsWide(int c) {
  int m, l, r, n;
  if (c < 0x1100) {
    return false;
  } else if (c < 0x10000) {
    l = 0;
    r = n = sizeof(kWides) / sizeof(kWides[0]);
    while (l < r) {
      m = (l & r) + ((l ^ r) >> 1);  // floor((a+b)/2)
      if (kWides[m][1] < c) {
        l = m + 1;
      } else {
        r = m;
      }
    }
    return l < n && kWides[l][0] <= c && c <= kWides[l][1];
  } else {
    l = 0;
    r = n = sizeof(kAstralWides) / sizeof(kAstralWides[0]);
    while (l < r) {
      m = (l & r) + ((l ^ r) >> 1);  // floor((a+b)/2)
      if (kAstralWides[m][1] < c) {
        l = m + 1;
      } else {
        r = m;
      }
    }
    return l < n && kAstralWides[l][0] <= c && c <= kAstralWides[l][1];
  }
}

pureconst int GetMonospaceCharacterWidth(int c) {
  return !IsControl(c) + IsWide(c);
}
