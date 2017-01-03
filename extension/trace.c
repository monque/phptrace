/**
 * Copyright 2016 Qihoo 360
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_trace.h"

#include "zend_extensions.h"
#include "SAPI.h"

#include "trace_comm.h"
#include "trace_time.h"
#include "trace_type.h"
#include "sds/sds.h"


/**
 * Trace Global
 * --------------------
 */
/* Debug output */
#if TRACE_DEBUG_OUTPUT
#define PTD(format, ...) fprintf(stderr, "[PTDebug:%d] " format "\n", __LINE__, ##__VA_ARGS__)
#else
#define PTD(format, ...)
#endif

/* Ctrl module */
#define CTRL_IS_ACTIVE()    pt_ctrl_is_active(&PTG(ctrl), PTG(pid))
#define CTRL_SET_INACTIVE() pt_ctrl_set_inactive(&PTG(ctrl), PTG(pid))

/* Ping process */
#define PING_UPDATE() PTG(ping) = pt_time_sec()
#define PING_TIMEOUT() (pt_time_sec() > PTG(ping) + PTG(idle_timeout))

/* Profiling */
#define PROFILING_SET(p) do { \
    p.wall_time = pt_time_usec(); \
    p.cpu_time = pt_cputime_usec(); \
    p.mem = zend_memory_usage(0 TSRMLS_CC); \
    p.mempeak = zend_memory_peak_usage(0 TSRMLS_CC); \
} while (0);

/* Flags of dotrace */
#define TRACE_TO_OUTPUT (1 << 0)
#define TRACE_TO_TOOL   (1 << 1)
#define TRACE_TO_NULL   (1 << 2)

/* Utils for PHP 7 */
#if PHP_VERSION_ID < 70000
#define P7_EX_OBJ(ex)   ex->object
#define P7_EX_OBJCE(ex) Z_OBJCE_P(ex->object)
#define P7_EX_OPARR(ex) ex->op_array
#define P7_STR(v)       v
#else
#define P7_EX_OBJ(ex)   Z_OBJ(ex->This)
#define P7_EX_OBJCE(ex) Z_OBJCE(ex->This)
#define P7_EX_OPARR(ex) (&(ex->func->op_array))
#define P7_STR(v)       ZSTR_VAL(v)
#endif

/**
 * Compatible with PHP 5.1, zend_memory_usage() is not available in 5.1.
 * AG(allocated_memory) is the value we want, but it available only when
 * MEMORY_LIMIT is ON during PHP compilation, so use zero instead for safe.
 */
#if PHP_VERSION_ID < 50200
#define zend_memory_usage(args...) 0
#define zend_memory_peak_usage(args...) 0
typedef unsigned long zend_uintptr_t;
#endif

#if TRACE_DEBUG
PHP_FUNCTION(trace_start);
PHP_FUNCTION(trace_end);
PHP_FUNCTION(trace_status);
#endif
//log:
PHP_FUNCTION(trace_add_log);
PHP_FUNCTION(trace_add_fatal);
PHP_FUNCTION(trace_set_env);
PHP_FUNCTION(trace_flush_log);



static void pt_frame_build(pt_frame_t *frame, zend_bool internal, unsigned char type, zend_execute_data *caller, zend_execute_data *ex, zend_op_array *op_array TSRMLS_DC);
static void pt_frame_destroy(pt_frame_t *frame TSRMLS_DC);
static int pt_frame_send(pt_frame_t *frame TSRMLS_DC);
#if PHP_VERSION_ID < 70000
static void pt_frame_set_retval(pt_frame_t *frame, zend_bool internal, zend_execute_data *ex, zend_fcall_info *fci TSRMLS_DC);
#endif

static void pt_status_build(pt_status_t *status, zend_bool internal, zend_execute_data *ex TSRMLS_DC);
static void pt_status_destroy(pt_status_t *status TSRMLS_DC);
static void pt_status_display(pt_status_t *status TSRMLS_DC);
static int pt_status_send(pt_status_t *status TSRMLS_DC);

static sds pt_repr_zval(zval *zv, int limit TSRMLS_DC);
static void pt_set_inactive(TSRMLS_D);

#if PHP_VERSION_ID < 50500
static void (*pt_ori_execute)(zend_op_array *op_array TSRMLS_DC);
static void (*pt_ori_execute_internal)(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);
ZEND_API void pt_execute(zend_op_array *op_array TSRMLS_DC);
ZEND_API void pt_execute_internal(zend_execute_data *execute_data, int return_value_used TSRMLS_DC);
#elif PHP_VERSION_ID < 70000
static void (*pt_ori_execute_ex)(zend_execute_data *execute_data TSRMLS_DC);
static void (*pt_ori_execute_internal)(zend_execute_data *execute_data_ptr, zend_fcall_info *fci, int return_value_used TSRMLS_DC);
ZEND_API void pt_execute_ex(zend_execute_data *execute_data TSRMLS_DC);
ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zend_fcall_info *fci, int return_value_used TSRMLS_DC);
#else
static void (*pt_ori_execute_ex)(zend_execute_data *execute_data);
static void (*pt_ori_execute_internal)(zend_execute_data *execute_data, zval *return_value);
ZEND_API void pt_execute_ex(zend_execute_data *execute_data);
ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zval *return_value);
#endif


/**
 * PHP Extension Init
 * --------------------
 */

ZEND_DECLARE_MODULE_GLOBALS(trace)

/* Make sapi_module accessable */
extern sapi_module_struct sapi_module;

/* True global resources - no need for thread safety here */
static int le_trace;

//log:
static pt_log_t pt_log;

/* Every user visible function must have an entry in trace_functions[]. */
const zend_function_entry trace_functions[] = {
#if TRACE_DEBUG
    PHP_FE(trace_start, NULL)
    PHP_FE(trace_end, NULL)
    PHP_FE(trace_status, NULL)
#endif
	//log:
	PHP_FE(trace_add_log, NULL)
	PHP_FE(trace_add_fatal, NULL)
	PHP_FE(trace_set_env, NULL)
	PHP_FE(trace_flush_log, NULL)
#ifdef PHP_FE_END
    PHP_FE_END  /* Must be the last line in trace_functions[] */
#else
    { NULL, NULL, NULL, 0, 0 }
#endif
};

zend_module_entry trace_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "trace",
    trace_functions,
    PHP_MINIT(trace),
    PHP_MSHUTDOWN(trace),
    PHP_RINIT(trace),
    PHP_RSHUTDOWN(trace),
    PHP_MINFO(trace),
#if ZEND_MODULE_API_NO >= 20010901
    TRACE_EXT_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#if PHP_VERSION_ID >= 70000 && defined(COMPILE_DL_TRACE) && defined(ZTS)
ZEND_TSRMLS_CACHE_DEFINE();
#endif

#ifdef COMPILE_DL_TRACE
ZEND_GET_MODULE(trace)
#endif

/* PHP_INI */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("trace.enable",    "1",    PHP_INI_SYSTEM, OnUpdateBool, enable, zend_trace_globals, trace_globals)
    STD_PHP_INI_ENTRY("trace.dotrace",   "0",    PHP_INI_SYSTEM, OnUpdateLong, dotrace, zend_trace_globals, trace_globals)
    STD_PHP_INI_ENTRY("trace.data_dir",  "/tmp", PHP_INI_SYSTEM, OnUpdateString, data_dir, zend_trace_globals, trace_globals)

	//log:������־�ļ�ini
	STD_PHP_INI_ENTRY("trace.dolog",    "1",    PHP_INI_SYSTEM, OnUpdateBool, dolog, zend_trace_globals, trace_globals)
	STD_PHP_INI_ENTRY("trace.log_dir",   "/tmp", PHP_INI_SYSTEM, OnUpdateString, log_dir, zend_trace_globals, trace_globals)
	STD_PHP_INI_ENTRY("trace.log_env",   "default", PHP_INI_SYSTEM, OnUpdateString, log_env, zend_trace_globals, trace_globals)
PHP_INI_END()

/* php_trace_init_globals */
static void php_trace_init_globals(zend_trace_globals *ptg)
{
    ptg->enable = ptg->dotrace = 0;
    ptg->data_dir = NULL;

	//log:������־�ļ�Ŀ¼
	ptg->log_dir = NULL;

    memset(&ptg->ctrl, 0, sizeof(ptg->ctrl));
    memset(ptg->ctrl_file, 0, sizeof(ptg->ctrl_file));

    ptg->sock_fd = -1;
    memset(ptg->sock_addr, 0, sizeof(ptg->sock_addr));

    ptg->pid = ptg->level = 0;

    ptg->ping = 0;
    ptg->idle_timeout = 30; /* hardcoded */

}


/**
 * PHP Extension Function
 * --------------------
 */
PHP_MINIT_FUNCTION(trace)
{
    ZEND_INIT_MODULE_GLOBALS(trace, php_trace_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    if (!PTG(enable)) {
        return SUCCESS;
    }

    /* Replace executor */
#if PHP_VERSION_ID < 50500
    pt_ori_execute = zend_execute;
    zend_execute = pt_execute;
#else
    pt_ori_execute_ex = zend_execute_ex;
    zend_execute_ex = pt_execute_ex;
#endif
    pt_ori_execute_internal = zend_execute_internal;
    zend_execute_internal = pt_execute_internal;

    /* Init comm module */
    snprintf(PTG(sock_addr), sizeof(PTG(sock_addr)), "%s/%s", PTG(data_dir), PT_COMM_FILENAME);

    /* Open ctrl module */
    snprintf(PTG(ctrl_file), sizeof(PTG(ctrl_file)), "%s/%s", PTG(data_dir), PT_CTRL_FILENAME);
    PTD("Ctrl module open %s", PTG(ctrl_file));
    if (pt_ctrl_create(&PTG(ctrl), PTG(ctrl_file)) < 0) {
        php_error(E_ERROR, "Trace ctrl file %s open failed", PTG(ctrl_file));
        return FAILURE;
    }

    /* Trace in CLI */
    if (PTG(dotrace) && sapi_module.name[0] == 'c' && sapi_module.name[1] == 'l' && sapi_module.name[2] == 'i') {
        PTG(dotrace) = TRACE_TO_OUTPUT;
    } else {
        PTG(dotrace) = 0;
    }

#if TRACE_DEBUG
    /* always do trace in debug mode */
    PTG(dotrace) |= TRACE_TO_NULL;
#endif

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(trace)
{
    UNREGISTER_INI_ENTRIES();

    if (!PTG(enable)) {
        return SUCCESS;
    }

    /* Restore original executor */
#if PHP_VERSION_ID < 50500
    zend_execute = pt_ori_execute;
#else
    zend_execute_ex = pt_ori_execute_ex;
#endif
    zend_execute_internal = pt_ori_execute_internal;

    /* Close ctrl module */
    PTD("Ctrl module close");
    pt_ctrl_close(&PTG(ctrl));

    /* Close comm module */
    if (PTG(sock_fd) != -1) {
        PTD("Comm socket close");
        pt_comm_close(PTG(sock_fd), NULL);
        PTG(sock_fd) = -1;
    }

    return SUCCESS;
}

PHP_RINIT_FUNCTION(trace)
{
#if PHP_VERSION_ID >= 70000 && defined(COMPILE_DL_TRACE) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    /* Anything needs pid, init here */
    if (PTG(pid) == 0) {
        PTG(pid) = getpid();
    }
    PTG(level) = 0;

	//log:
	pt_log_init(&pt_log);
	strcpy(pt_log.dir, PTG(log_dir));
	strcpy(pt_log.env, PTG(log_env));

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(trace)
{
	//log:
	//todo
	
	char *method = pt_server_query("REQUEST_METHOD", strlen("REQUEST_METHOD"));
	if(method != NULL){
	 	strncpy(pt_log.method, method, 256);
	}
	
	char *remote_ip = pt_server_query("REMOTE_ADDR", strlen("REMOTE_ADDR"));
	if(remote_ip != NULL){
		strncpy(pt_log.remote_ip, remote_ip, 256);
	}

	char *refer = pt_server_query("HTTP_REFERER", strlen("HTTP_REFERER"));
	if(refer != NULL){
	 	strncpy(pt_log.refer, refer, 4096);
	}

	char *cookie = pt_server_query("HTTP_COOKIE", strlen("HTTP_COOKIE"));
	if(cookie != NULL){
	 	strncpy(pt_log.cookie, cookie, 4096);
	}

	char *request_uri = pt_server_query("REQUEST_URI", strlen("REQUEST_URI"));
	if(request_uri != NULL){
	 	strncpy(pt_log.request_uri, request_uri, 4096);
	}

	pt_log_write(1, &pt_log);

	zend_hash_destroy(pt_log.ht);
	zend_hash_destroy(pt_log.frame_ht);

	if(pt_log.fd > 0){
		close(pt_log.fd);
		pt_log.fd = 0;
	}

	if(pt_log.wf_fd > 0){
		close(pt_log.wf_fd);
		pt_log.wf_fd = 0;
	}
		
    return SUCCESS;
}

PHP_MINFO_FUNCTION(trace)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "trace support", "enabled");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}


/**
 * Trace Interface
 * --------------------
 */
#if TRACE_DEBUG
PHP_FUNCTION(trace_start)
{
    PTG(dotrace) |= TRACE_TO_OUTPUT;
}

PHP_FUNCTION(trace_end)
{
    PTG(dotrace) &= ~TRACE_TO_OUTPUT;
}

PHP_FUNCTION(trace_status)
{
    pt_status_t status;
    pt_status_build(&status, 1, EG(current_execute_data) TSRMLS_CC);
    pt_status_display(&status TSRMLS_CC);
    pt_status_destroy(&status TSRMLS_CC);
}
#endif

//log: ���Ӽ�¼��־����,Ŀǰֻ֧��key value��ʽ
//trace_add_log("aaa", "bbb");
PHP_FUNCTION(trace_add_log)
{
	char *key = NULL;
	char *value = NULL;
	
	zval *z_value;
	int key_len;
	int value_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &value, &value_len) == FAILURE) {
		RETURN_FALSE;
	}
	
	MAKE_STD_ZVAL(z_value);
	ZVAL_STRING(z_value, value, 1);	
	
	zend_hash_update(pt_log.ht, key, strlen(key) + 1, &z_value, sizeof(zval *), NULL);

}


PHP_FUNCTION(trace_add_fatal)
{
	char *key = NULL;
	char *value = NULL;
	
	int key_len;
	int value_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &value, &value_len) == FAILURE) {
		RETURN_FALSE;
	}

	snprintf(pt_log.wf_log, PT_LOG_DATA_STRLEN, "%s[\"%s\"]", key, value);

}


//log:
PHP_FUNCTION(trace_set_env)
{
	int value_len;
	char *value = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE) {
		RETURN_FALSE;
	}

	//todo �ж�
	if(value != NULL && value[0]){
		strncpy(pt_log.env, value, 256);
	}
}

PHP_FUNCTION(trace_flush_log)
{
	pt_log_write(1, &pt_log);

	zend_hash_clean(pt_log.ht);
	zend_hash_clean(pt_log.frame_ht);

	if(pt_log.fd > 0){
		close(pt_log.fd);
		pt_log.fd = 0;
	}

	if(pt_log.wf_fd > 0){
		close(pt_log.wf_fd);
		pt_log.wf_fd = 0;
	}
		
}


/**
 * Trace Manipulation of Frame
 * --------------------
 */
static void pt_frame_build(pt_frame_t *frame, zend_bool internal, unsigned char type, zend_execute_data *caller, zend_execute_data *ex, zend_op_array *op_array TSRMLS_DC)
{
    unsigned int i;
    zval **args;
    zend_function *zf;

    /* init */
    memset(frame, 0, sizeof(pt_frame_t));

#if PHP_VERSION_ID < 50500
    if (internal || ex) {
        op_array = ex->op_array;
        zf = ex->function_state.function;
    } else {
        zf = (zend_function *) op_array;
    }
#elif PHP_VERSION_ID < 70000
    zf = ex->function_state.function;
#else
    zf = ex->func;
#endif

    /* types, level */
    frame->type = type;
    frame->functype = internal ? PT_FUNC_INTERNAL : 0x00;
    frame->level = PTG(level);

    /* args init */
    args = NULL;
    frame->arg_count = 0;
    frame->args = NULL;

    /* names */
    if (zf->common.function_name) {
        /* functype, class name */
#if PHP_VERSION_ID < 70000
        if (caller && P7_EX_OBJ(caller)) {
#else
        if (ex && P7_EX_OBJ(ex)) {
#endif
            frame->functype |= PT_FUNC_MEMBER;
            /* User care about which method is called exactly, so use
             * zf->common.scope->name instead of ex->object->name. */
            if (zf->common.scope) {
                frame->class = sdsnew(P7_STR(zf->common.scope->name));
            } else {
                /* TODO zend uses zend_get_object_classname() in
                 * debug_print_backtrace() */
                php_error(E_WARNING, "Trace catch a entry with ex->object but without zf->common.scope");
            }

        } else if (zf->common.scope) {
            frame->functype |= PT_FUNC_STATIC;
            frame->class = sdsnew(P7_STR(zf->common.scope->name));
        } else {
            frame->functype |= PT_FUNC_NORMAL;
        }

        /* function name */
        if (strcmp(P7_STR(zf->common.function_name), "{closure}") == 0) {
            frame->function = sdscatprintf(sdsempty(), "{closure:%s:%d-%d}", P7_STR(zf->op_array.filename), zf->op_array.line_start, zf->op_array.line_end);
        } else if (strcmp(P7_STR(zf->common.function_name), "__lambda_func") == 0) {
            frame->function = sdscatprintf(sdsempty(), "{lambda:%s}", P7_STR(zf->op_array.filename));
#if PHP_VERSION_ID >= 50414
        } else if (zf->common.scope && zf->common.scope->trait_aliases) {
            /* Use trait alias instead real function name.
             * There is also a bug "#64239 Debug backtrace changed behavior
             * since 5.4.10 or 5.4.11" about this
             * https://bugs.php.net/bug.php?id=64239.*/
            frame->function = sdsnew(P7_STR(zend_resolve_method_name(P7_EX_OBJ(ex) ? P7_EX_OBJCE(ex) : zf->common.scope, zf)));
#endif
        } else {
            frame->function = sdsnew(P7_STR(zf->common.function_name));
        }

        /* args */
#if PHP_VERSION_ID < 50300
        /* TODO support fetching arguments in backtrace */
        if (EG(argument_stack).top >= 2) {
            frame->arg_count = (int)(zend_uintptr_t) *(EG(argument_stack).top_element - 2);
            args = (zval **)(EG(argument_stack).top_element - 2 - frame->arg_count);
        }
#elif PHP_VERSION_ID < 70000
        if (caller && caller->function_state.arguments) {
            frame->arg_count = (int)(zend_uintptr_t) *(caller->function_state.arguments);
            args = (zval **)(caller->function_state.arguments - frame->arg_count);
        }
#else
        frame->arg_count = ZEND_CALL_NUM_ARGS(ex);
#endif
        if (frame->arg_count > 0) {
            frame->args = calloc(frame->arg_count, sizeof(sds));
			//log:
			frame->o_args = args;
        }

#if PHP_VERSION_ID < 70000
        for (i = 0; i < frame->arg_count; i++) {
            frame->args[i] = pt_repr_zval(args[i], 32 TSRMLS_CC);
        }
#else
        if (frame->arg_count) {
            i = 0;
            zval *p = ZEND_CALL_ARG(ex, 1);
            if (ex->func->type == ZEND_USER_FUNCTION) {
                uint32_t first_extra_arg = ex->func->op_array.num_args;

                if (first_extra_arg && frame->arg_count > first_extra_arg) {
                    while (i < first_extra_arg) {
                        frame->args[i++] = pt_repr_zval(p++, 32);
                    }
                    p = ZEND_CALL_VAR_NUM(ex, ex->func->op_array.last_var + ex->func->op_array.T);
                }
            }
            while(i < frame->arg_count) {
                frame->args[i++] = pt_repr_zval(p++, 32);
            }
        }
#endif

    } else {
        int add_filename = 1;
        long ev = 0;

#if ZEND_EXTENSION_API_NO < 220100525
        if (caller) {
            ev = caller->opline->op2.u.constant.value.lval;
        } else if (op_array && op_array->opcodes) {
            ev = op_array->opcodes->op2.u.constant.value.lval;
        }
#elif PHP_VERSION_ID < 70000
        if (caller) {
            ev = caller->opline->extended_value;
        } else if (op_array && op_array->opcodes) {
            ev = op_array->opcodes->extended_value;
        }
#else
        if (caller && caller->opline) {
            ev = caller->opline->extended_value;
        }
#endif

        /* special user function */
        switch (ev) {
            case ZEND_INCLUDE_ONCE:
                frame->functype |= PT_FUNC_INCLUDE_ONCE;
                frame->function = "include_once";
                break;
            case ZEND_REQUIRE_ONCE:
                frame->functype |= PT_FUNC_REQUIRE_ONCE;
                frame->function = "require_once";
                break;
            case ZEND_INCLUDE:
                frame->functype |= PT_FUNC_INCLUDE;
                frame->function = "include";
                break;
            case ZEND_REQUIRE:
                frame->functype |= PT_FUNC_REQUIRE;
                frame->function = "require";
                break;
            case ZEND_EVAL:
                frame->functype |= PT_FUNC_EVAL;
                frame->function = "{eval}"; /* TODO add eval code */
                add_filename = 0;
                break;
            default:
                /* should be function main */
                frame->functype |= PT_FUNC_NORMAL;
                frame->function = "{main}";
                add_filename = 0;
                break;
        }
        frame->function = sdsnew(frame->function);
        if (add_filename) {
            frame->arg_count = 1;
            frame->args = calloc(frame->arg_count, sizeof(sds));
            frame->args[0] = sdscatrepr(sdsempty(), P7_STR(zf->op_array.filename), strlen(P7_STR(zf->op_array.filename)));
        }
    }

#if PHP_VERSION_ID >= 70000
    /* FIXME Sometimes execute_data->opline can be a interger NOT pointer.
     * I dont know how to handle it, this just make it works. */
    if (caller && caller->opline && caller->prev_execute_data &&
            caller->func && caller->func->op_array.opcodes == NULL) {
        caller = caller->prev_execute_data;
    }

    /* skip internal handler */
    if (caller && caller->opline && caller->prev_execute_data &&
            caller->opline->opcode != ZEND_DO_FCALL &&
            caller->opline->opcode != ZEND_DO_ICALL &&
            caller->opline->opcode != ZEND_DO_UCALL &&
            caller->opline->opcode != ZEND_DO_FCALL_BY_NAME &&
            caller->opline->opcode != ZEND_INCLUDE_OR_EVAL) {
        caller = caller->prev_execute_data;
    }
#endif

    /* lineno
     * The method we try to detect line number and filename is different
     * between Zend's debug_backtrace().
     * Because 1. Performance, so we won't use loop to find the valid op_array.
     * 2. And still want to catch internal function call, such as
     * call_user_func().  */
    if (caller && caller->opline) {
        frame->lineno = caller->opline->lineno;
    } else if (caller && caller->prev_execute_data && caller->prev_execute_data->opline) {
        frame->lineno = caller->prev_execute_data->opline->lineno; /* try using prev */
    } else if (op_array && op_array->opcodes) {
        frame->lineno = op_array->opcodes->lineno;
    /* Uncomment to use definition lineno if entry lineno is null, but we won't :P
     * } else if (caller != EG(current_execute_data) && EG(current_execute_data)->opline) {
     *     frame->lineno = EG(current_execute_data)->opline->lineno; [> try using current <]
     */
    } else {
        frame->lineno = 0;
    }

    /* filename */
#if PHP_VERSION_ID < 70000
    if (caller && caller->op_array) {
        op_array = caller->op_array;
    } else if (caller && caller->prev_execute_data && caller->prev_execute_data->op_array) {
        op_array = caller->prev_execute_data->op_array; /* try using prev */
    }
#else
    if (caller->func && ZEND_USER_CODE(caller->func->common.type)) {
        op_array = &(caller->func->op_array);
    } else if (caller->prev_execute_data && caller->prev_execute_data->func &&
            ZEND_USER_CODE(caller->prev_execute_data->func->common.type)) {
        op_array = &(caller->prev_execute_data->func->op_array); /* try using prev */
    }
#endif
    /* Same as upper
     * } else if (caller != EG(current_execute_data) && EG(current_execute_data)->op_array) {
     *     op_array = EG(current_execute_data)->op_array [> try using current <]
     * }
     */
    if (op_array) {
        frame->filename = sdsnew(P7_STR(op_array->filename));
    } else {
        frame->filename = NULL;
    }
}

static void pt_frame_destroy(pt_frame_t *frame TSRMLS_DC)
{
    int i;

    sdsfree(frame->filename);
    sdsfree(frame->class);
    sdsfree(frame->function);
    if (frame->args && frame->arg_count) {
        for (i = 0; i < frame->arg_count; i++) {
            sdsfree(frame->args[i]);
        }
        free(frame->args);
    }
    sdsfree(frame->retval);
}

#if PHP_VERSION_ID < 70000
static void pt_frame_set_retval(pt_frame_t *frame, zend_bool internal, zend_execute_data *ex, zend_fcall_info *fci TSRMLS_DC)
{
    zval *retval = NULL;

    if (internal) {
        /* Ensure there is no exception occurs before fetching return value.
         * opline would be replaced by the Exception's opline if exception was
         * thrown which processed in function zend_throw_exception_internal().
         * It may cause a SEGMENTATION FAULT if we get the return value from a
         * exception opline. */
#if PHP_VERSION_ID >= 50500
        if (fci != NULL) {
            retval = *fci->retval_ptr_ptr;
        } else if (ex->opline && !EG(exception)) {
            retval = EX_TMP_VAR(ex, ex->opline->result.var)->var.ptr;
        }
#else
        if (ex->opline && !EG(exception)) {
#if PHP_VERSION_ID < 50400
            retval = ((temp_variable *)((char *) ex->Ts + ex->opline->result.u.var))->var.ptr;
#else
            retval = ((temp_variable *)((char *) ex->Ts + ex->opline->result.var))->var.ptr;
#endif
        }
#endif
    } else if (*EG(return_value_ptr_ptr)) {
        retval = *EG(return_value_ptr_ptr);
    }

    if (retval) {
        frame->retval = pt_repr_zval(retval, 32 TSRMLS_CC);
    }
}
#endif

static int pt_frame_send(pt_frame_t *frame TSRMLS_DC)
{
    size_t len;
    pt_comm_message_t *msg;

    /* build */
    len = pt_type_len_frame(frame);
    if (pt_comm_build_msg(&msg, len, PT_MSG_RET) == -1) {
        php_error(E_WARNING, "Trace build message failed, size: %ld", len);
        return -1;
    }
    pt_type_pack_frame(frame, msg->data);
    msg->pid = PTG(pid); /* TODO move to seperated init command */

    /* send */
    PTD("send message type: 0x%08x len: %d", msg->type, msg->len);
    if (pt_comm_send_msg(PTG(sock_fd), msg) == -1) {
        PTD("send message failed, errmsg: %s", strerror(errno));
        return -1;
    }

    return 0;
}


/**
 * Trace Manipulation of Status
 * --------------------
 */
static void pt_status_build(pt_status_t *status, zend_bool internal, zend_execute_data *ex TSRMLS_DC)
{
    int i;
    zend_execute_data *ex_ori = ex;

    /* init */
    memset(status, 0, sizeof(pt_status_t));

    /* common */
    status->php_version = PHP_VERSION;
    status->sapi_name = sapi_module.name;

    /* profile */
    status->mem = zend_memory_usage(0 TSRMLS_CC);
    status->mempeak = zend_memory_peak_usage(0 TSRMLS_CC);
    status->mem_real = zend_memory_usage(1 TSRMLS_CC);
    status->mempeak_real = zend_memory_peak_usage(1 TSRMLS_CC);

    /* request */
    status->request_method = (char *) SG(request_info).request_method;
    status->request_uri = SG(request_info).request_uri;
    status->request_query = SG(request_info).query_string;
    status->request_time = SG(global_request_time);
    status->request_script = SG(request_info).path_translated;
    status->proto_num = SG(request_info).proto_num;

    /* arguments */
    status->argc = SG(request_info).argc;
    status->argv = SG(request_info).argv;

    /* frame */
    for (i = 0; ex; ex = ex->prev_execute_data, i++) ; /* calculate stack depth */
    status->frame_count = i;
    if (status->frame_count) {
        status->frames = calloc(status->frame_count, sizeof(pt_frame_t));
        for (i = 0, ex = ex_ori; i < status->frame_count && ex; i++, ex = ex->prev_execute_data) {
            pt_frame_build(status->frames + i, internal, PT_FRAME_STACK, ex, ex, NULL TSRMLS_CC);
            status->frames[i].level = 1;
        }
    } else {
        status->frames = NULL;
    }
}

static void pt_status_destroy(pt_status_t *status TSRMLS_DC)
{
    int i;

    if (status->frames && status->frame_count) {
        for (i = 0; i < status->frame_count; i++) {
            pt_frame_destroy(status->frames + i TSRMLS_CC);
        }
        free(status->frames);
    }
}

static void pt_status_display(pt_status_t *status TSRMLS_DC)
{
    int i;

    zend_printf("------------------------------- Status --------------------------------\n");
    zend_printf("PHP Version:       %s\n", status->php_version);
    zend_printf("SAPI:              %s\n", status->sapi_name);

    zend_printf("memory:            %.2fm\n", status->mem / 1048576.0);
    zend_printf("memory peak:       %.2fm\n", status->mempeak / 1048576.0);
    zend_printf("real-memory:       %.2fm\n", status->mem_real / 1048576.0);
    zend_printf("real-memory peak   %.2fm\n", status->mempeak_real / 1048576.0);

    zend_printf("------------------------------- Request -------------------------------\n");
    if (status->request_method) {
    zend_printf("request method:    %s\n", status->request_method);
    }
    zend_printf("request time:      %f\n", status->request_time);
    if (status->request_uri) {
    zend_printf("request uri:       %s\n", status->request_uri);
    }
    if (status->request_query) {
    zend_printf("request query:     %s\n", status->request_query);
    }
    if (status->request_script) {
    zend_printf("request script:    %s\n", status->request_script);
    }
    zend_printf("proto_num:         %d\n", status->proto_num);

    if (status->argc) {
        zend_printf("------------------------------ Arguments ------------------------------\n");
        for (i = 0; i < status->argc; i++) {
            zend_printf("$%-10d        %s\n", i, status->argv[i]);
        }
    }

    if (status->frame_count) {
        zend_printf("------------------------------ Backtrace ------------------------------\n");
        for (i = 0; i < status->frame_count; i++) {
            pt_type_display_frame(status->frames + i, 0, "#%-3d", i);
        }
    }
}

static int pt_status_send(pt_status_t *status TSRMLS_DC)
{
    size_t len;
    pt_comm_message_t *msg;

    /* build */
    len = pt_type_len_status(status);
    if (pt_comm_build_msg(&msg, len, PT_MSG_RET) == -1) {
        php_error(E_WARNING, "Trace build message failed, size: %ld", len);
        return -1;
    }
    pt_type_pack_status(status, msg->data);
    msg->pid = PTG(pid); /* TODO move to seperated init command */

    /* send */
    PTD("send message type: 0x%08x len: %d", msg->type, msg->len);
    if (pt_comm_send_msg(PTG(sock_fd), msg) == -1) {
        PTD("send message failed, errmsg: %s", strerror(errno));
        return -1;
    }

    return 0;
}


/**
 * Trace Misc Function
 * --------------------
 */
static sds pt_repr_zval(zval *zv, int limit TSRMLS_DC)
{
    int tlen = 0;
    char buf[256], *tstr = NULL;
    sds result;

#if PHP_VERSION_ID >= 70000
    zend_string *class_name;
#endif

    /* php_var_export_ex is a good example */
    switch (Z_TYPE_P(zv)) {
#if PHP_VERSION_ID < 70000
        case IS_BOOL:
            if (Z_LVAL_P(zv)) {
                return sdsnew("true");
            } else {
                return sdsnew("false");
            }
#else
        case IS_TRUE:
            return sdsnew("true");
        case IS_FALSE:
            return sdsnew("false");
#endif
        case IS_NULL:
            return sdsnew("NULL");
        case IS_LONG:
            snprintf(buf, sizeof(buf), "%ld", Z_LVAL_P(zv));
            return sdsnew(buf);
        case IS_DOUBLE:
            snprintf(buf, sizeof(buf), "%.*G", (int) EG(precision), Z_DVAL_P(zv));
            return sdsnew(buf);
        case IS_STRING:
            tlen = (limit <= 0 || Z_STRLEN_P(zv) < limit) ? Z_STRLEN_P(zv) : limit;
            result = sdscatrepr(sdsempty(), Z_STRVAL_P(zv), tlen);
            if (limit > 0 && Z_STRLEN_P(zv) > limit) {
                result = sdscat(result, "...");
            }
            return result;
        case IS_ARRAY:
            /* TODO more info */
            return sdscatprintf(sdsempty(), "array(%d)", zend_hash_num_elements(Z_ARRVAL_P(zv)));
        case IS_OBJECT:
#if PHP_VERSION_ID < 70000
            if (Z_OBJ_HANDLER(*zv, get_class_name)) {
                Z_OBJ_HANDLER(*zv, get_class_name)(zv, (const char **) &tstr, (zend_uint *) &tlen, 0 TSRMLS_CC);
                result = sdscatprintf(sdsempty(), "object(%s)#%d", tstr, Z_OBJ_HANDLE_P(zv));
                efree(tstr);
            } else {
                result = sdscatprintf(sdsempty(), "object(unknown)#%d", Z_OBJ_HANDLE_P(zv));
            }
#else
            class_name = Z_OBJ_HANDLER_P(zv, get_class_name)(Z_OBJ_P(zv));
            result = sdscatprintf(sdsempty(), "object(%s)#%d", P7_STR(class_name), Z_OBJ_HANDLE_P(zv));
			zend_string_release(class_name);
#endif
            return result;
        case IS_RESOURCE:
#if PHP_VERSION_ID < 70000
            tstr = (char *) zend_rsrc_list_get_rsrc_type(Z_LVAL_P(zv) TSRMLS_CC);
            return sdscatprintf(sdsempty(), "resource(%s)#%ld", tstr ? tstr : "Unknown", Z_LVAL_P(zv));
#else
            tstr = (char *) zend_rsrc_list_get_rsrc_type(Z_RES_P(zv) TSRMLS_CC);
            return sdscatprintf(sdsempty(), "resource(%s)#%ld", tstr ? tstr : "Unknown", Z_RES_P(zv)->handle);
        case IS_UNDEF:
            return sdsnew("{undef}");
#endif
        default:
            return sdsnew("{unknown}");
    }
}

static void pt_set_inactive(TSRMLS_D)
{
    /* Toggle off dotrace flag */
    PTG(dotrace) &= ~TRACE_TO_TOOL;

    /* Inactive ctrl module */
    PTD("Ctrl set inactive");
    CTRL_SET_INACTIVE();

    /* Close comm module */
    if (PTG(sock_fd) != -1) {
        PTD("Comm socket close");
        pt_comm_close(PTG(sock_fd), NULL);
        PTG(sock_fd) = -1;
    }
}


/**
 * Trace Executor Replacement
 * --------------------
 */
#if PHP_VERSION_ID < 50500
ZEND_API void pt_execute_core(int internal, zend_execute_data *execute_data, zend_op_array *op_array, int rvu TSRMLS_DC)
#elif PHP_VERSION_ID < 70000
ZEND_API void pt_execute_core(int internal, zend_execute_data *execute_data, zend_fcall_info *fci, int rvu TSRMLS_DC)
#else
ZEND_API void pt_execute_core(int internal, zend_execute_data *execute_data, zval *return_value)
#endif
{
    long dotrace;
    zend_bool dobailout = 0;
    zend_execute_data *caller = execute_data;
#if PHP_VERSION_ID < 70000
    zval *retval = NULL;
#else
    zval retval;
#endif
    pt_comm_message_t *msg;
    pt_frame_t frame;
    int msg_type;

#if PHP_VERSION_ID >= 70000
    if (execute_data->prev_execute_data) {
        caller = execute_data->prev_execute_data;
    }
#elif PHP_VERSION_ID >= 50500
    /* In PHP 5.5 and later, execute_data is the data going to be executed, not
     * the entry point, so we switch to previous data. The internal function is
     * a exception because it's no need to execute by op_array. */
    if (!internal && execute_data->prev_execute_data) {
        caller = execute_data->prev_execute_data;
    }
#endif

    /* Check ctrl module */
    if (CTRL_IS_ACTIVE()) {
        /* Open comm socket */
        if (PTG(sock_fd) == -1) {
            PTD("Comm socket connect to %s", PTG(sock_addr));
            PTG(sock_fd) = pt_comm_connect(PTG(sock_addr));
            if (PTG(sock_fd) == -1) {
                PTD("Connect to %s failed, errmsg: %s", PTG(sock_addr), strerror(errno));
                pt_set_inactive(TSRMLS_C);
                goto exec;
            }
            PING_UPDATE();
        }

        /* Handle message */
        while (1) {
            msg_type = pt_comm_recv_msg(PTG(sock_fd), &msg);
            PTD("recv message type: 0x%08x len: %d", msg_type, msg->len);
            switch (msg_type) {
                case PT_MSG_PEERDOWN:
                case PT_MSG_ERR_SOCK:
                case PT_MSG_ERR_BUF:
                case PT_MSG_INVALID:
                    PTD("recv message error errno: %d errmsg: %s", errno, strerror(errno));
                    pt_set_inactive(TSRMLS_C);
                    goto exec;

                case PT_MSG_EMPTY:
                    PTD("handle EMPTY");
                    if (PING_TIMEOUT()) {
                        PTD("Ping timeout");
                        pt_set_inactive(TSRMLS_C);
                    }
                    goto exec;

                case PT_MSG_DO_TRACE:
                    PTD("handle DO_TRACE");
                    PTG(dotrace) |= TRACE_TO_TOOL;
                    break;

                case PT_MSG_DO_STATUS:
                    PTD("handle DO_STATUS");
                    pt_status_t status;
                    pt_status_build(&status, internal, caller TSRMLS_CC);
                    pt_status_send(&status TSRMLS_CC);
                    pt_status_destroy(&status TSRMLS_CC);
                    break;

                case PT_MSG_DO_PING:
                    PTD("handle DO_PING");
                    PING_UPDATE();
                    break;

                default:
                    php_error(E_NOTICE, "Trace unknown message received with type 0x%08x", msg->type);
                    break;
            }
        }
    } else if (PTG(sock_fd) != -1) { /* comm socket still opend */
        pt_set_inactive(TSRMLS_C);
    }

exec:
    /* Assigning to a LOCAL VARIABLE at begining to prevent value changed
     * during executing. And whether send frame mesage back is controlled by
     * GLOBAL VALUE and LOCAL VALUE both because comm-module may be closed in
     * recursion and sending on exit point will be affected. */
    dotrace = PTG(dotrace);

    //log:
    //todo
    int is_log = 0;
	int dolog = PTG(dolog);
	if(dolog){
        is_log = pt_check_method(execute_data TSRMLS_CC);

		if(is_log == 0){
			dolog = 0;
		}
	}

    PTG(level)++;

    if (dotrace || dolog) {
#if PHP_VERSION_ID < 50500
        pt_frame_build(&frame, internal, PT_FRAME_ENTRY, caller, execute_data, op_array TSRMLS_CC);
#else
        pt_frame_build(&frame, internal, PT_FRAME_ENTRY, caller, execute_data, NULL TSRMLS_CC);
#endif
        /* Register return value ptr */
#if PHP_VERSION_ID < 70000
        if (!internal && EG(return_value_ptr_ptr) == NULL) {
            EG(return_value_ptr_ptr) = &retval;
        }
#else
        if (!internal && execute_data->return_value == NULL) {
            ZVAL_UNDEF(&retval);
            Z_VAR_FLAGS(retval) = 0;
            execute_data->return_value = &retval;
        }
#endif

        PROFILING_SET(frame.entry);

        /* Send frame message */
        if (dotrace & TRACE_TO_TOOL) {
            pt_frame_send(&frame TSRMLS_CC);
        }
        if (dotrace & TRACE_TO_OUTPUT) {
            pt_type_display_frame(&frame, 1, "> ");
        }
    }

    /* Call original under zend_try. baitout will be called when exit(), error
     * occurs, exception thrown and etc, so we have to catch it and free our
     * resources. */
    zend_try {
#if PHP_VERSION_ID < 50500
        if (internal) {
            if (pt_ori_execute_internal) {
                pt_ori_execute_internal(execute_data, rvu TSRMLS_CC);
            } else {
                execute_internal(execute_data, rvu TSRMLS_CC);
            }
        } else {
            pt_ori_execute(op_array TSRMLS_CC);
        }
#elif PHP_VERSION_ID < 70000
        if (internal) {
            if (pt_ori_execute_internal) {
                pt_ori_execute_internal(execute_data, fci, rvu TSRMLS_CC);
            } else {
                execute_internal(execute_data, fci, rvu TSRMLS_CC);
            }
        } else {
            pt_ori_execute_ex(execute_data TSRMLS_CC);
        }
#else
        if (internal) {
            if (pt_ori_execute_internal) {
                pt_ori_execute_internal(execute_data, return_value);
            } else {
                execute_internal(execute_data, return_value);
            }
        } else {
            pt_ori_execute_ex(execute_data);
        }
#endif
    } zend_catch {
        dobailout = 1;
        /* call zend_bailout() at the end of this function, we still want to
         * send message. */
    } zend_end_try();


    if (dotrace || dolog) {
        PROFILING_SET(frame.exit);
		
        if (!dobailout) {
#if PHP_VERSION_ID < 50500
            pt_frame_set_retval(&frame, internal, execute_data, NULL TSRMLS_CC);
#elif PHP_VERSION_ID < 70000
            pt_frame_set_retval(&frame, internal, execute_data, fci TSRMLS_CC);
#else
            if (return_value) { /* internal */
                frame.retval = pt_repr_zval(return_value, 32);
            } else if (execute_data->return_value) { /* user function */
                frame.retval = pt_repr_zval(execute_data->return_value, 32);
            }
#endif
        }
        frame.type = PT_FRAME_EXIT;

        /* Send frame message */
        if (PTG(dotrace) & TRACE_TO_TOOL & dotrace) {
            pt_frame_send(&frame TSRMLS_CC);
        }
        if (PTG(dotrace) & TRACE_TO_OUTPUT & dotrace) {
            pt_type_display_frame(&frame, 1, "< ");
        }

#if PHP_VERSION_ID < 70000
        /* Free return value */
        if (!internal && retval != NULL) {
            zval_ptr_dtor(&retval);
            EG(return_value_ptr_ptr) = NULL;
        }
#endif

		//log:
		//todo ���ӿ���
		if(dolog){
			pt_record_frame(&frame, &pt_log);
		}

        pt_frame_destroy(&frame TSRMLS_CC);
    }

    PTG(level)--;

    if (dobailout) {
        zend_bailout();
    }
}


#if PHP_VERSION_ID < 50500
ZEND_API void pt_execute(zend_op_array *op_array TSRMLS_DC)
{
    pt_execute_core(0, EG(current_execute_data), op_array, 0 TSRMLS_CC);
}

ZEND_API void pt_execute_internal(zend_execute_data *execute_data, int return_value_used TSRMLS_DC)
{
    pt_execute_core(1, execute_data, NULL, return_value_used TSRMLS_CC);
}
#elif PHP_VERSION_ID < 70000
ZEND_API void pt_execute_ex(zend_execute_data *execute_data TSRMLS_DC)
{
    pt_execute_core(0, execute_data, NULL, 0 TSRMLS_CC);
}

ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zend_fcall_info *fci, int return_value_used TSRMLS_DC)
{
    pt_execute_core(1, execute_data, fci, return_value_used TSRMLS_CC);
}
#else
ZEND_API void pt_execute_ex(zend_execute_data *execute_data)
{
    pt_execute_core(0, execute_data, NULL);
}

ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
    pt_execute_core(1, execute_data, return_value);
}
#endif




