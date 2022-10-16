/* Copyright (C) 2015-2017 Open Information Security Foundation
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
 * TODO: Update the \author in this file and detect-stun.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "stun_rust" keyword to allow content
 * inspections on the decoded stun application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-stun-message_type.h"
#include "app-layer-parser.h"
#include "detect-engine-build.h"
#include "rust.h"

static int DetectStunmessage_typeSetup(DetectEngineCtx *, Signature *, const char *);
static uint8_t DetectEngineInspectStunmessage_type(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
#ifdef UNITTESTS
static void DetectStunmessage_typeRegisterTests(void);
#endif
static int g_stun_rust_id = 0;

void DetectStunmessage_typeRegister(void)
{
    sigmatch_table[DETECT_AL_STUN_MESSAGE_TYPE].name = "stun_message_type";
    sigmatch_table[DETECT_AL_STUN_MESSAGE_TYPE].desc =
            "Stun content modifier to match on the stun buffers";
    sigmatch_table[DETECT_AL_STUN_MESSAGE_TYPE].Setup = DetectStunmessage_typeSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_STUN_MESSAGE_TYPE].RegisterTests = DetectStunmessage_typeRegisterTests;
#endif
    sigmatch_table[DETECT_AL_STUN_MESSAGE_TYPE].flags |= SIGMATCH_NOOPT;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2("stun_message_type", ALPROTO_STUN, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectStunmessage_type, NULL);
    DetectAppLayerInspectEngineRegister2("stun_message_type", ALPROTO_STUN, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectStunmessage_type, NULL);

    g_stun_rust_id = DetectBufferTypeGetByName("stun_message_type");

    SCLogNotice("Stun application layer detect registered.");
}

static int DetectStunmessage_typeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    s->init_data->list = g_stun_rust_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_STUN) != 0)
        return -1;

    return 0;
}

static uint8_t DetectEngineInspectStunmessage_type(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint8_t ret = 0;
    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    if (flags & STREAM_TOSERVER) {
        rs_stun_get_request_buffer(txv, &data, &data_len);
    } else if (flags & STREAM_TOCLIENT) {
        rs_stun_get_response_buffer(txv, &data, &data_len);
    }

    if (data != NULL) {
        ret = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)data, data_len, 0, DETECT_CI_FLAGS_SINGLE,
                DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    }

    SCLogNotice("Returning %d.", ret);
    return ret;
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "flow-util.h"
#include "stream-tcp.h"

static int DetectStunmessage_typeTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p;
    TcpSession tcp;
    ThreadVars tv;
    Signature *s;

    uint8_t request[] = "12:Hello World!";

    /* Setup flow. */
    memset(&f, 0, sizeof(Flow));
    memset(&tcp, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    p = UTHBuildPacket(request, sizeof(request), IPPROTO_TCP);
    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_STUN;
    f.protoctx = (void *)&tcp;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;
    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    /* This rule should match. */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                      "msg:\"STUN Test Rule\"; "
                                      "stun_message_type; content:\"World!\"; "
                                      "sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    /* This rule should not match. */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                      "msg:\"STUN Test Rule\"; "
                                      "stun_message_type; content:\"W0rld!\"; "
                                      "sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_STUN, STREAM_TOSERVER, request, sizeof(request));

    /* Check that we have app-layer state. */
    FAIL_IF_NULL(f.alstate);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));

    /* Cleanup. */
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

static void DetectStunmessage_typeRegisterTests(void)
{
    UtRegisterTest("DetectStunmessage_typeTest", DetectStunmessage_typeTest);
}
#endif /* UNITTESTS */
