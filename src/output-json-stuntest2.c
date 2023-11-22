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
 * TODO: Update \author in this file and in output-json-stuntest2.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer StunTest2.
 */

#include "suricata-common.h"
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

#include "app-layer-stuntest2.h"
#include "output-json-stuntest2.h"
#include "rust.h"

typedef struct LogStunTest2FileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogStunTest2FileCtx;

typedef struct LogStunTest2LogThread_ {
    LogStunTest2FileCtx *stuntest2log_ctx;
    OutputJsonThreadCtx *ctx;
} LogStunTest2LogThread;

static int JsonStunTest2Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonStunTest2Logger");
    LogStunTest2LogThread *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(
            p, LOG_DIR_PACKET, "stuntest2", NULL, thread->stuntest2log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "stuntest2");
    if (!rs_stuntest2_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputStunTest2LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogStunTest2FileCtx *stuntest2log_ctx = (LogStunTest2FileCtx *)output_ctx->data;
    SCFree(stuntest2log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputStunTest2LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogStunTest2FileCtx *stuntest2log_ctx = SCCalloc(1, sizeof(*stuntest2log_ctx));
    if (unlikely(stuntest2log_ctx == NULL)) {
        return result;
    }
    stuntest2log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(stuntest2log_ctx);
        return result;
    }
    output_ctx->data = stuntest2log_ctx;
    output_ctx->DeInit = OutputStunTest2LogDeInitCtxSub;

    SCLogNotice("StunTest2 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_STUNTEST2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonStunTest2LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogStunTest2LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogStunTest2.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->stuntest2log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->stuntest2log_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonStunTest2LogThreadDeinit(ThreadVars *t, void *data)
{
    LogStunTest2LogThread *thread = (LogStunTest2LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonStunTest2LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_STUNTEST2, "eve-log", "JsonStunTest2Log",
            "eve-log.stuntest2", OutputStunTest2LogInitSub, ALPROTO_STUNTEST2, JsonStunTest2Logger,
            JsonStunTest2LogThreadInit, JsonStunTest2LogThreadDeinit, NULL);

    SCLogNotice("StunTest2 JSON logger registered.");
}
