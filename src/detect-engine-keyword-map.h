/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Juliana Fajardini <jufajardini@oisf.net>
 */

#ifndef SURICATA_DETECT_ENGINE_KEYWORD_MAP_H
#define SURICATA_DETECT_ENGINE_KEYWORD_MAP_H

#include "suricata-common.h"

void DetectKeywordAppLayerMapRegister(uint16_t keyword_id, int buffer_id);
void DetectKeywordAppLayerProtoRegister(uint16_t keyword_id, AppProto alproto);
bool DetectKeywordAppLayerPrintHooksList(uint16_t keyword_id, const char *prefix);
void DetectKeywordAppLayerProtoList(uint16_t keyword_id, const char *prefix);
void DetectKeywordAppLayerListingEnable(void);
void DetectKeywordAppLayerMapFree(void);
bool DetectKeywordListByAppProto(const char *proto_name);

#endif /* SURICATA_DETECT_ENGINE_KEYWORD_MAP_H */
