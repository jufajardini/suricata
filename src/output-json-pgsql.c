/* Copyright (C) 2018-2021 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and in output-json-pgsql.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author Juliana Fajardini <jufajardini@oisf.net>
 *
 * Implement JSON/eve logging app-layer Pgsql.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-pgsql.h"
#include "output-json-pgsql.h"
#include "rust.h"

typedef struct LogPgsqlFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogPgsqlFileCtx;

typedef struct LogPgsqlLogThread_ {
    LogPgsqlFileCtx *pgsqllog_ctx;
    OutputJsonThreadCtx *ctx;
} LogPgsqlLogThread;

static int JsonPgsqlLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    PgsqlTransaction *pgsql_tx = tx;
    LogPgsqlLogThread *thread = thread_data;
    SCLogNotice("Logging pgsql transaction %" PRIu64 ".", pgsql_tx->tx_id);

    // TODO must figure out the best way to pass that new argument
    JsonBuilder *jb =
            CreateEveHeader(p, LOG_DIR_PACKET, "pgsql", NULL, thread->pgsqllog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "pgsql");

    if (!rs_pgsql_logger_log(tx, jb)) {
        goto error;
    }
    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread->ctx);
    jb_free(jb);

    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static OutputInitResult OutputPgsqlLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    SCLogNotice("PostgreSQL log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_PGSQL);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

static TmEcode JsonPgsqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogPgsqlLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogPgsql.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->pgsqllog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->pgsqllog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonPgsqlLogThreadDeinit(ThreadVars *t, void *data)
{
    LogPgsqlLogThread *thread = (LogPgsqlLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonPgsqlLogRegister(void)
{
    /* PGSQL_START_REMOVE */
    if (ConfGetNode("app-layer.protocols.pgsql") == NULL) {
        return;
    }
    /* PGSQL_END_REMOVE */
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_PGSQL, "eve-log", "JsonPgsqlLog", "eve-log.postgresql",
            OutputPgsqlLogInitSub, ALPROTO_PGSQL, JsonPgsqlLogger, JsonPgsqlLogThreadInit,
            JsonPgsqlLogThreadDeinit, NULL);

    SCLogNotice("PostgreSQL JSON logger registered.");
}
