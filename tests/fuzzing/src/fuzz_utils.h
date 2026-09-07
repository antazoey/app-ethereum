#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "shared_context.h"
#include "nbgl_use_case.h"
#include "status_words.h"
#include "tx_ctx.h"
#include "cmd_safe_account.h"
#include "ui_utils.h"

extern void reset_app_context(void);
extern void init_fuzzing_environment(void);
