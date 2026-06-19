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

#include "suricata-common.h"
#include "rust.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "detect-engine-keyword-map.h"

typedef struct DetectKeywordAppLayerMap_ {
    uint16_t keyword_id;
    int buffer_id;
    /* set only when buffer_name is NULL: the app-layer protocol this keyword
     * is valid for. ALPROTO_UNKNOWN otherwise. */
    AppProto alproto;
    struct DetectKeywordAppLayerMap_ *next;
} DetectKeywordAppLayerMap;
static DetectKeywordAppLayerMap *g_keyword_applayer_map = NULL;
static DetectKeywordAppLayerMap *g_keyword_applayer_map_tail = NULL;

/* Enable recording g_keyword_applayer_map for CLI listings only. */
static bool g_keyword_applayer_listing = false;

void DetectKeywordAppLayerListingEnable(void)
{
    g_keyword_applayer_listing = true;
}

static DetectKeywordAppLayerMap *DetectKeywordAppLayerMapNew(uint16_t keyword_id)
{
    DetectKeywordAppLayerMap *map = SCCalloc(1, sizeof(*map));
    if (unlikely(map == NULL))
        FatalError("failed to allocate keyword app-layer map entry");
    map->keyword_id = keyword_id;
    if (g_keyword_applayer_map_tail == NULL) {
        g_keyword_applayer_map = map;
    } else {
        g_keyword_applayer_map_tail->next = map;
    }
    g_keyword_applayer_map_tail = map;
    return map;
}

void DetectKeywordAppLayerMapFree(void)
{
    DetectKeywordAppLayerMap *map = g_keyword_applayer_map;
    while (map != NULL) {
        DetectKeywordAppLayerMap *next = map->next;
        SCFree(map);
        /* we don't free buffer_name as it's a borrowed static string */
        map = next;
    }
    g_keyword_applayer_map = NULL;
    g_keyword_applayer_map_tail = NULL;
    g_keyword_applayer_listing = false;
}

void DetectKeywordAppLayerMapRegister(uint16_t keyword_id, int buffer_id)
{
    if (!g_keyword_applayer_listing)
        return;
    DetectKeywordAppLayerMap *m = DetectKeywordAppLayerMapNew(keyword_id);
    DEBUG_VALIDATE_BUG_ON(buffer_id < 0);
    m->buffer_id = buffer_id;
}

/** \brief Associate a keyword with an app-layer protocol directly.
 *
 *  For when the proto cannot be derived from a buffer (as there isn't one). */
void DetectKeywordAppLayerProtoRegister(uint16_t keyword_id, AppProto alproto)
{
    if (!g_keyword_applayer_listing)
        return;
    DetectKeywordAppLayerMap *m = DetectKeywordAppLayerMapNew(keyword_id);
    m->alproto = alproto;
    m->buffer_id = -1;
}

/** \brief Whether an inspection-buffer list has any app-layer inspect engine,
 *         i.e. it is genuinely an app-layer buffer rather than a packet or
 *         transform buffer that merely shares a keyword name. */
static bool DetectBufferTypeHasAppLayerHook(int sm_list)
{
    const DetectEngineAppInspectionEngine *e = DetectGetAppInspectionEngine();
    for (; e != NULL; e = e->next) {
        if (e->sm_list == (uint16_t)sm_list)
            return true;
    }
    return false;
}

static void DetectBufferTypeHooksList(int sm_list, const char *prefix)
{
    char indent[64];
    snprintf(indent, sizeof(indent), "%s  ", prefix);

    const DetectEngineAppInspectionEngine *e = DetectGetAppInspectionEngine();
    for (; e != NULL; e = e->next) {
        if (e->sm_list != (uint16_t)sm_list)
            continue;

        const char *alproto_name = AppProtoToString(e->alproto);
        const uint8_t dir_flag = e->dir == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT;
        const char *state_name =
                AppLayerParserGetStateNameById(IPPROTO_TCP, e->alproto, e->progress, dir_flag);
        if (state_name == NULL)
            /* UDP-only proto? */
            state_name =
                    AppLayerParserGetStateNameById(IPPROTO_UDP, e->alproto, e->progress, dir_flag);
        if (state_name == NULL)
            state_name = "(no hook name defined)";

        printf("%s%-10s %-10s %s\n", indent, alproto_name, e->dir == 0 ? "to_server" : "to_client",
                state_name);
    }
}

/* Fixed cap on the number of (deduplicated) inspection-buffer lists / app-layer
 * protocols collected per keyword. Real maximum today is 2 (e.g. urilen ->
 * http_uri + http_raw_uri). */
#define DETECT_KEYWORD_MAX_LISTS 4
/** \brief Collect the inspection-buffer list ids a keyword is associated with.
 *
 *  Sources, in priority order:
 *    1. explicit keyword -> buffer map;
 *    2. if the keyword has no explicit entry, fall back to a buffer registered
 *       under the keyword's own name or alias.
 *
 *  \param lists  output array of (deduplicated) sm_list ids
 *  \param max    capacity of lists
 *  \retval number of list ids written to lists
 */
static int DetectKeywordGetAppLayerLists(uint16_t keyword_id, int *lists, int max)
{
    int cnt = 0;
    bool had_explicit = false;
    for (const DetectKeywordAppLayerMap *m = g_keyword_applayer_map; m != NULL; m = m->next) {
        if (m->keyword_id != keyword_id)
            continue;
        had_explicit = true;
        if (m->buffer_id < 0)
            continue;
        const int sm_list = m->buffer_id;
        bool dup = false;
        for (int i = 0; i < cnt; i++) {
            if (lists[i] == sm_list) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            DEBUG_VALIDATE_BUG_ON(cnt >= max);
            if (cnt < max)
                lists[cnt++] = sm_list;
        }
    }
    if (!had_explicit) {
        /* a keyword with no explicit Map/Proto entry is matched to a buffer
         * registered under its own name or alias. This assumes keyword name
         * (or alias) == buffer name. */
        const char *name = sigmatch_table[keyword_id].name;
        int sm_list;
        if (name == NULL) {
            sm_list = -1;
        } else {
            sm_list = DetectBufferTypeGetByName(name);
        }
        if (sm_list < 0 && sigmatch_table[keyword_id].alias != NULL)
            sm_list = DetectBufferTypeGetByName(sigmatch_table[keyword_id].alias);
        if (sm_list >= 0 && DetectBufferTypeHasAppLayerHook(sm_list) && cnt < max)
            lists[cnt++] = sm_list;
    }
    return cnt;
}

/** \brief Collect the app-layer protocols a keyword is directly associated
 *         with.
 *
 *  \retval number of (deduplicated) protocols written to protos
 */
static int DetectKeywordGetAppLayerProtos(uint16_t keyword_id, AppProto *protos, int max)
{
    int cnt = 0;
    for (const DetectKeywordAppLayerMap *m = g_keyword_applayer_map; m != NULL; m = m->next) {
        if (m->keyword_id != keyword_id)
            continue;
        if (m->buffer_id >= 0 || m->alproto == ALPROTO_UNKNOWN)
            continue;
        bool dup = false;
        for (int i = 0; i < cnt; i++) {
            if (protos[i] == m->alproto) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            DEBUG_VALIDATE_BUG_ON(cnt >= max);
            if (cnt < max)
                protos[cnt++] = m->alproto;
        }
    }
    return cnt;
}

/** \brief Print a list of app-layer hooks for a given keyword, if those exist.
 *
 * \retval false if no hooks are associated with the keyword, true if a list is printed.
 */
bool DetectKeywordAppLayerPrintHooksList(uint16_t keyword_id, const char *prefix)
{
    int lists[DETECT_KEYWORD_MAX_LISTS];
    const int n = DetectKeywordGetAppLayerLists(keyword_id, lists, DETECT_KEYWORD_MAX_LISTS);
    if (n == 0)
        return false;
    printf("%sApp-layer state hooks:\n", prefix);
    for (int i = 0; i < n; i++)
        DetectBufferTypeHooksList(lists[i], prefix);
    return true;
}

/** \brief Print the app-layer protocol(s) a keyword is tied to when it has NO
 *         inspection-buffer / parser-state hook (post-match actions, obsolete
 *         aliases, ...). */
void DetectKeywordAppLayerProtoList(uint16_t keyword_id, const char *prefix)
{
    AppProto protos[DETECT_KEYWORD_MAX_LISTS];
    const int proto_count =
            DetectKeywordGetAppLayerProtos(keyword_id, protos, DETECT_KEYWORD_MAX_LISTS);
    for (int i = 0; i < proto_count; i++)
        printf("%sApp-layer: %s (no app-layer state hook)\n", prefix, AppProtoToString(protos[i]));
}

static bool DetectKeywordProtoMatch(AppProto queried, AppProto registered)
{
    /* HTTP functions as an alias do HTTP1 here, (same as in default firewall policies) */
    if (queried == registered)
        return true;
    return false;
}

static bool DetectKeywordRegisteredForProto(uint16_t keyword_id, AppProto alproto)
{
    int lists[DETECT_KEYWORD_MAX_LISTS];
    const int n = DetectKeywordGetAppLayerLists(keyword_id, lists, DETECT_KEYWORD_MAX_LISTS);
    const DetectEngineAppInspectionEngine *e = DetectGetAppInspectionEngine();
    for (int i = 0; i < n; i++) {
        for (; e != NULL; e = e->next) {
            if (e->sm_list == (uint16_t)lists[i] && DetectKeywordProtoMatch(alproto, e->alproto)) {
                return true;
            }
        }
    }
    AppProto protos[DETECT_KEYWORD_MAX_LISTS];
    const int proto_count =
            DetectKeywordGetAppLayerProtos(keyword_id, protos, DETECT_KEYWORD_MAX_LISTS);
    for (int i = 0; i < proto_count; i++) {
        if (DetectKeywordProtoMatch(alproto, protos[i]))
            return true;
    }
    return false;
}

static int DetectKeywordListForProto(AppProto alproto)
{
    int count = 0;
    for (size_t i = 0; i < (size_t)DETECT_TBLSIZE_IDX; i++) {
        const char *name = sigmatch_table[i].name;
        if (name == NULL || strlen(name) == 0)
            continue;
        if (name[0] == '_' || strcmp(name, "template") == 0)
            continue;
        if (!DetectKeywordRegisteredForProto((uint16_t)i, alproto))
            continue;
        if (count == 0)
            printf("===== %s keywords =====\n", AppProtoToString(alproto));
        printf("%s\n", name);
        count++;
    }
    return count;
}

bool DetectKeywordListByAppProto(const char *proto_name)
{
    if (proto_name != NULL) {
        AppProto alproto = StringToAppProto(proto_name);
        if (alproto == ALPROTO_UNKNOWN) {
            return false;
        }
        if (alproto == ALPROTO_HTTP)
            alproto = ALPROTO_HTTP1;
        DetectKeywordListForProto(alproto);
        return true;
    }

    /* start with first real app-proto, avoiding unknown and failed */
    for (AppProto a = ALPROTO_HTTP1; a < g_alproto_max; a++) {
        DetectKeywordListForProto(a);
    }
    return true;
}
