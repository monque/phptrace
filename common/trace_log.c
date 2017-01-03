
#include "trace_log.h"

#define PT_FILE_RDONLY          O_RDONLY
#define PT_FILE_WRONLY          O_WRONLY
#define PT_FILE_RDWR            O_RDWR
#define PT_FILE_CREATE_OR_OPEN  O_CREAT
#define PT_FILE_OPEN            0
#define PT_FILE_TRUNCATE        O_CREAT|O_TRUNC
#define PT_FILE_APPEND          O_WRONLY|O_APPEND
#define PT_FILE_NONBLOCK        O_NONBLOCK
#define PT_FILE_DEFAULT_ACCESS  0666


void pt_log_init(pt_log_t *log)
{
			
	log->start_time = pt_time_usec();

	log->fd = 0;
	log->wf_fd = 0;
	

	log->dir[0] = 0;
	log->env[0] = 0;
	
	log->cookie[0] = 0;
	log->method[0] = 0;
	log->refer[0] = 0;
	log->remote_ip[0] = 0;
	log->request_uri[0] = 0;
	log->server_ip[0] = 0;
	log->trace_order = 0;

	log->wf_log[0] = 0;
	
	ALLOC_HASHTABLE(log->ht);	
	zend_hash_init(log->ht, 50, NULL, ZVAL_PTR_DTOR, 0);

	ALLOC_HASHTABLE(log->frame_ht);	
	zend_hash_init(log->frame_ht, 50, NULL, ZVAL_PTR_DTOR, 0);
}


static int pt_log_fd_init(pt_log_t *log)
{
	if(log->fd > 0){
		return 0;
	}
	
	zval *ret = NULL;
	zend_class_entry **ce = NULL;
	zend_function    *fptr;
	zval *obj = NULL;

    //兼容老php从类中获取环境变量
	if(!strcmp(log->env, "default")){
		if(zend_hash_find(EG(class_table), "initlogenv", strlen("initlogenv") + 1, (void **) &ce) == SUCCESS) {
			MAKE_STD_ZVAL(obj);	
			if (zend_hash_find(&((*ce)->function_table), "getcurrapp", strlen("getcurrapp") + 1, (void **)&fptr) == SUCCESS) {
				object_init_ex(obj, *ce); 
				zend_call_method(&obj, *ce, NULL, "getcurrapp", strlen("getcurrapp"), &ret, 0, NULL, NULL TSRMLS_CC);

				if(ret != NULL){
					char *dev = Z_STRVAL_P(ret);
					if(dev[0] != '0'){
						strncpy(log->env, Z_STRVAL_P(ret), 256); 
					}
				}
			}
			zval_ptr_dtor(&obj);
		}
	}

	char dir[256];
	snprintf(dir, 256, "%s/%s.new", log->dir, log->env);
	if(pt_mkdir_recursive(dir) < 0) {
		return -1;
	}

    char tmpbuf[128];
	time_t rawtime;
	struct tm * timeinfo;
	 
    rawtime = time(&tmpbuf);
    timeinfo = localtime(&rawtime);
    strftime(tmpbuf, 128, "%Y%m%d%H", timeinfo);

	char file[1024];
	snprintf(file, 1024, "%s/%s.log.%s", dir, log->env, tmpbuf);
	log->fd = open(file, PT_FILE_CREATE_OR_OPEN|PT_FILE_APPEND, PT_FILE_DEFAULT_ACCESS);
    if(log->fd < 0){
		printf("open(%s) failed. Error: %s[%d]", file, strerror(errno), errno);
		return -1;
	}

	if(log->wf_log[0]){
		//wf日志
		snprintf(file, 1024, "%s/%s.log.wf.%s", dir, log->env, tmpbuf);
		log->wf_fd = open(file, PT_FILE_CREATE_OR_OPEN|PT_FILE_APPEND, PT_FILE_DEFAULT_ACCESS);

	    if(log->wf_fd < 0){
			printf("open(%s) failed. Error: %s[%d]", file, strerror(errno), errno);
			return -1;
		}
	}
	
    return 0;
}

void pt_log_debug(char* type, char* info, pt_log_t *log)
{
	int fd = pt_log_fd_init(log);
	if(fd == -1){
		return NULL;
	}

	char date_str[PT_LOG_DATA_STRLEN];
	snprintf(date_str, PT_LOG_DATA_STRLEN, "[%s]%s\n", type, info); 
	
	write(log->fd, date_str, strlen(date_str));
}

void pt_log_write(int level, pt_log_t *log)
{		
	int fd = pt_log_fd_init(log);
	if(fd == -1){
		return NULL;
	}

	const char *level_str;
	switch (level)
	{
		case PT_LOG_DEBUG:
			level_str = "DEBUG";
			break;
		case PT_LOG_FATAL:
			level_str = "FATAL";
			break;
		case PT_LOG_WARN:
			level_str = "WARN";
			break;
		default:
			level_str = "INFO";
			break;
	}

	time_t t;
	struct tm *p;
	t = time(NULL);
	p = localtime(&t);

    //解析post数据
    char post_str[PT_LOG_INFO_STRLEN] = {0};
	zval *post = PG(http_globals)[TRACK_VARS_POST];
	HashTable *post_ht = Z_ARRVAL_P(post);
	pt_loop_hashtable(post_ht, post_str, "%s=%s&");


	//自定义链路
	char log_str[PT_LOG_INFO_STRLEN] = {0};
	pt_loop_hashtable(log->ht, log_str, " %s[%s]");

	//抓取函数链路
	char frame_str[PT_LOG_INFO_STRLEN] = {0};
	pt_loop_hashtable(log->frame_ht, log_str, " %s[%s]");

	char data_str[PT_LOG_DATA_STRLEN] = {0};
	snprintf(data_str, PT_LOG_DATA_STRLEN, "%s: %s [%d/%d/%d:%d:%d:%d] \"%s %s\" ERRNO[%d] REFERER[%s] COOKIE[%s] POST[%s] ts[%.6f] %s %s\n", 
		level_str, log->remote_ip, p->tm_year + 1900, p->tm_mon+1, p->tm_mday , p->tm_hour, p->tm_min, p->tm_sec, \
		log->method, log->request_uri, 0, log->refer, log->cookie, post_str, \
		(pt_time_usec() - log->start_time)/ 1000000.0, log_str, frame_str);

	write(log->fd, data_str, strlen(data_str));

    //todo
	//close(log->fd);

	if(log->wf_log[0]){
		snprintf(data_str, PT_LOG_DATA_STRLEN, "%s: %s [%d/%d/%d:%d:%d:%d] \"%s %s\" ERRNO[%d] REFERER[%s] COOKIE[%s] POST[%s] ts[%.6f] %s\n", 
			"FATAL", log->remote_ip, p->tm_year + 1900, p->tm_mon+1, p->tm_mday , p->tm_hour, p->tm_min, p->tm_sec, \
			log->method, log->request_uri, 0, log->refer, log->cookie, post_str, \
			(pt_time_usec() - log->start_time)/ 1000000.0, log->wf_log);
		write(log->wf_fd, data_str, strlen(data_str));
		close(log->wf_fd);
	}
	
}

char* pt_server_query(char * name, int len) 
{
    zval **carrier, **ret;
    carrier = &PG(http_globals)[TRACK_VARS_SERVER];
    
    if (!carrier || !(*carrier)) {
        return NULL;
    }

    if (zend_hash_find(Z_ARRVAL_PP(carrier), name, len + 1, (void **)&ret) == FAILURE) {
        return NULL;
    }

	return Z_STRVAL_P(*ret);
	
}

void pt_record_frame(pt_frame_t *frame, pt_log_t *log)
{
	zval *z_value;
	char msg_info[PT_LOG_BUFFER_SIZE];
	char key[20];

	MAKE_STD_ZVAL(z_value);
	if(frame->arg_count >  0  && strcmp(frame->function, "curl_exec") == 0){
		char   *url_code;
		double  ts_code;
		long    http_code;	
		
		php_curl *ch;
		ch = ZEND_FETCH_RESOURCE_NO_RETURN(ch, php_curl *, frame->o_args, -1, le_curl_name, le_curl);

		//url
		int flag = 0;
		if (curl_easy_getinfo(ch->cp, CURLINFO_EFFECTIVE_URL, &url_code) != CURLE_OK) {	
			flag = -1;
		}

		//ts
		if (curl_easy_getinfo(ch->cp, CURLINFO_TOTAL_TIME, &ts_code) != CURLE_OK) {	
			flag = -1;
		}

		//http_code
		if (curl_easy_getinfo(ch->cp, CURLINFO_HTTP_CODE, &http_code) != CURLE_OK) {	
			flag = -1;
		}

		if(flag < 0){
			printf("curl(%s) failed. Error", "curl_easy_getinfo");
			return NULL;
		}
		
		snprintf(msg_info, PT_LOG_BUFFER_SIZE, "\"%s\" \"%s\" %0.3f %d \"%s\" %d", url_code, "", ts_code, ch->err.no, pt_curl_msg[ch->err.no], http_code);
		ZVAL_STRING(z_value, msg_info, 1);

		sprintf(key, "curl[##%d]", log->trace_order++);
		zend_hash_update(log->frame_ht, key, strlen(key) + 1, &z_value, sizeof(zval *), NULL);

		//记录wf信息
		if(ch->err.no && !log->wf_log[0]){
			snprintf(log->wf_log, PT_LOG_BUFFER_SIZE, "curl[\"%s\" \"%s\" %0.3f %d \"%s\" %d]", url_code, "", ts_code * 1000, ch->err.no, pt_curl_msg[ch->err.no], http_code);			
		}else if(http_code != 200 && !log->wf_log[0]){
			snprintf(log->wf_log, PT_LOG_BUFFER_SIZE, "curl[\"%s\" \"%s\" %0.3f %d \"%s\" %d]", url_code, "", ts_code * 1000, ch->err.no, "HTTP_STATUS_ERROR", http_code);			
		}
	}
	else if(frame->arg_count >  0  && !strcmp(frame->class, "Redis")){
		snprintf(msg_info, PT_LOG_BUFFER_SIZE, "\"%s\" %s %.3f", frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0);
		ZVAL_STRING(z_value, msg_info, 1);

		sprintf(key, "Redis[##%d]", log->trace_order++);
		zend_hash_update(log->frame_ht, key, strlen(key) + 1, &z_value, sizeof(zval *), NULL);

		//捕捉redis异常
		if (EG(exception) && instanceof_function(Z_OBJCE_P(EG(exception)), redis_exception_ce TSRMLS_CC)) {
			pt_set_exception(redis_exception_ce, frame, log);
		}

	}
	else if(frame->arg_count >  0  && !strcmp(frame->class, "Memcached")){
		snprintf(msg_info, PT_LOG_BUFFER_SIZE, "\"%s\" %s %.3f", frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0);
		ZVAL_STRING(z_value, msg_info, 1);

		sprintf(key, "Memcached[##%d]", log->trace_order++);
		zend_hash_update(log->frame_ht, key, strlen(key) + 1, &z_value, sizeof(zval *), NULL);

		if (EG(This) && Z_OBJ_HT_P(EG(This))->get_class_entry) {
			zend_class_entry *ce;				
			ce = zend_get_class_entry(EG(This) TSRMLS_CC);

			//捕获Memcaced异常
			pt_set_memcached_exception(ce, frame, log);

		}

	}else if(frame->arg_count >  0  && !strcmp(frame->class, "mysqli")){
		snprintf(msg_info, PT_LOG_BUFFER_SIZE, "\"%s\" %s %.3f", frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0);
		ZVAL_STRING(z_value, msg_info, 1);

		sprintf(key, "Mysql[##%d]", log->trace_order++);
		zend_hash_update(log->frame_ht, key, strlen(key) + 1, &z_value, sizeof(zval *), NULL);

		if (EG(This) && Z_OBJ_HT_P(EG(This))->get_class_entry) {
			zend_class_entry *ce;				
			ce = zend_get_class_entry(EG(This) TSRMLS_CC);

			//捕获mysql异常
			pt_set_mysqli_exception(ce, frame, log);

		}
	}

}

//todo TSRMLS_DC
int pt_check_method(zend_execute_data *ex TSRMLS_DC){
	zend_function *zf;

	zf = ex->function_state.function;

    char *function = zf->common.function_name;
   
	
	if(function && strcmp(function, "curl_exec") == 0){
		return 1;
	}

	if (zf->common.scope){
		char *class = zf->common.scope->name;
		if(class && strcmp(class, "Redis") == 0){
			return 1;
		}
	}

	if (zf->common.scope){
		char *class = zf->common.scope->name;
		if(class && strcmp(class, "Memcached") == 0){
			if(function && !strcmp(function, "setOption")){
				return 0;
			}
			return 1;
		}
	}

	
	if (zf->common.scope){
		char *class = zf->common.scope->name;
		if(class && strcmp(class, "mysqli") == 0){
			if(function && !strcmp(function, "options")){
				return 0;
			}
			return 1;
		}
	}
	return 0;
	
}

static void pt_set_memcached_exception(zend_class_entry *entry, pt_frame_t *frame, pt_log_t *log)
{
	zval *message, *code;
	zend_call_method(&EG(This), Z_OBJCE_P(EG(This)), NULL, "getresultcode", sizeof("getresultcode")-1, &code, 0, NULL, NULL TSRMLS_CC);
	
	if(Z_LVAL_P(code) > 0){
		zend_call_method(&EG(This), Z_OBJCE_P(EG(This)), NULL, "getresultmessage", sizeof("getresultmessage")-1, &message, 0, NULL, NULL TSRMLS_CC);

		if(message != NULL && !log->wf_log[0]){
			snprintf(log->wf_log, PT_LOG_DATA_STRLEN, "%s[\"%s\" %s %.3f \"Uncaught %s:%ld\"]", entry->name, frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0, Z_STRVAL_P(message), Z_LVAL_P(code));

		}
		
	}
}


static void pt_set_exception(zend_class_entry *entry, pt_frame_t *frame, pt_log_t *log)
{
	zval *str, *file, *line, *message, *code;

	file = zend_read_property(entry, EG(exception), "file", sizeof("file")-1, 1 TSRMLS_CC);				
	line = zend_read_property(entry, EG(exception), "line", sizeof("line")-1, 1 TSRMLS_CC);
	message = zend_read_property(entry, EG(exception), "message", sizeof("message")-1, 1 TSRMLS_CC);
	code = zend_read_property(entry, EG(exception), "code", sizeof("code")-1, 1 TSRMLS_CC);
		
	file = (Z_STRLEN_P(file) > 0) ? file : NULL;				
	line = (Z_TYPE_P(line) == IS_LONG) ? line : NULL;
	message = (Z_STRLEN_P(message) > 0) ? message : NULL;				
	code = (Z_TYPE_P(code) == IS_LONG) ? code : NULL;

	if(!log->wf_log[0]){
		snprintf(log->wf_log, PT_LOG_DATA_STRLEN, "%s[##0][\"%s\" %s %.3f \"Uncaught %s:%ld, file:%s line:%ld\"]", Z_OBJCE_P(EG(exception))->name, frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0, Z_STRVAL_P(message), Z_LVAL_P(code), Z_STRVAL_P(file), Z_LVAL_P(line));
	}
}

static void pt_set_mysqli_exception(zend_class_entry *entry, pt_frame_t *frame, pt_log_t *log)
{
	zval *message, *code;
	code = zend_read_property(Z_OBJCE_P(EG(This)), EG(This), "connect_errno", sizeof("connect_errno")-1, 1 TSRMLS_CC);				
	code = (Z_TYPE_P(code) == IS_LONG) ? code : NULL;
	if(Z_LVAL_P(code) > 0){
		message = zend_read_property(Z_OBJCE_P(EG(This)), EG(This), "connect_error", sizeof("connect_error")-1, 1 TSRMLS_CC);				
		message = (Z_STRLEN_P(message) > 0) ? message : NULL;
		if(message != NULL && !log->wf_log[0]){
			snprintf(log->wf_log, PT_LOG_DATA_STRLEN, "%s[\"%s\" %s %.3f \"Uncaught %s:%ld\"]", entry->name, frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0, Z_STRVAL_P(message), Z_LVAL_P(code));

		}
	}else{
		code = zend_read_property(Z_OBJCE_P(EG(This)), EG(This), "errno", sizeof("errno")-1, 1 TSRMLS_CC);				
		code = (Z_TYPE_P(code) == IS_LONG) ? code : NULL;
		if(Z_LVAL_P(code) > 0 && !log->wf_log[0]){
			message = zend_read_property(Z_OBJCE_P(EG(This)), EG(This), "error", sizeof("error")-1, 1 TSRMLS_CC);				
			message = (Z_STRLEN_P(message) > 0) ? message : NULL;
			if(message != NULL){
				snprintf(log->wf_log, PT_LOG_DATA_STRLEN, "%s[\"%s\" %s %.3f \"Uncaught %s:%ld\"]", entry->name, frame->function, frame->args[0], (frame->exit.wall_time - frame->entry.wall_time) / 1000000.0, Z_STRVAL_P(message), Z_LVAL_P(code));
				
			}
		}

	}
}


static void pt_loop_hashtable(HashTable *ht, char *frame_str, const char *format)
{
	HashPosition         pos;
    zval               **z_val = NULL;
	char* key;
	int key_len;
	int num_key;
    char* value= NULL;
	
	int len = 0;
	char info_str[PT_LOG_BUFFER_SIZE] = {0};
	
	for(zend_hash_internal_pointer_reset_ex(ht, &pos);
		zend_hash_get_current_data_ex(ht, (void **)&z_val, &pos) == SUCCESS;
		zend_hash_move_forward_ex(ht, &pos)) {	
			value = Z_STRVAL_PP(z_val);
			zend_hash_get_current_key_ex(ht, &key, &key_len, &num_key, 0, &pos);

		snprintf(info_str, PT_LOG_BUFFER_SIZE, format, key, value);
		//todo 溢出
		if(len < PT_LOG_INFO_STRLEN){
			strncat(frame_str, info_str, PT_LOG_BUFFER_SIZE);
			len += strlen(info_str);
		}
	}
}

static int pt_mkdir_recursive(const char *dir)
{
    char tmp[1024];
    strncpy(tmp, dir, 1024);
    int i, len = strlen(tmp);

    if (dir[len - 1] != '/')
    {
        strcat(tmp, "/");
    }

    len = strlen(tmp);

    for (i = 1; i < len; i++)
    {
        if (tmp[i] == '/')
        {
            tmp[i] = 0;
            if (access(tmp, R_OK) != 0)
            {
                if (mkdir(tmp, 0755) == -1)
                {
                    return -1;
                }
            }
            tmp[i] = '/';
        }
    }
    return 0;
}



