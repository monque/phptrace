#ifndef CM_LOG_H_
#define CM_LOG_H_

#include <fcntl.h>
#include <stdio.h>
#include <time.h>

#include "php.h"
#include "SAPI.h"

#define HAVE_CURL 1

#include "ext/curl/php_curl.h"

#include "trace_time.h"
#include "trace_type.h"


#define PT_LOG_DATA_STRLEN  8092
#define PT_LOG_INFO_STRLEN  4096
#define PT_LOG_BUFFER_SIZE 1024

#define PT_LOG_DEBUG           0
#define PT_LOG_INFO            1
#define PT_LOG_WARN            2
#define PT_LOG_FATAL           3

extern zend_class_entry *redis_exception_ce;

typedef struct {
	int fd;
	int wf_fd;
	int64_t start_time;
	char dir[256];
	char env[256];

	char method[256];
	char remote_ip[256];
	char server_ip[256];
	char refer[4096];
	char cookie[4096];
	char request_uri[4096];
	char wf_log[PT_LOG_DATA_STRLEN];
	
	HashTable* ht;
	HashTable* frame_ht;

	int trace_order;
}pt_log_t;


void pt_log_init(pt_log_t *log);

char* pt_server_query(char * name, int len);

void pt_log_debug(char* type, char* info, pt_log_t *log);

void pt_log_write(int level, pt_log_t *log);

void pt_record_frame(pt_frame_t *frame, pt_log_t *log);

int pt_check_method(zend_execute_data *ex TSRMLS_DC);

static int pt_mkdir_recursive(const char *dir);

static void pt_loop_hashtable(HashTable *ht, char *frame_str, const char *format);

static void pt_set_exception(zend_class_entry *entry, pt_frame_t *frame, pt_log_t *log);

static void pt_set_memcached_exception(zend_class_entry *entry, pt_frame_t *frame, pt_log_t *log);

static void pt_set_mysqli_exception(zend_class_entry *entry, pt_frame_t *frame, pt_log_t *log);

const static char pt_curl_msg[91][256] = {"CURLE_SUCCESS", "CURLE_UNSUPPORTED_PROTOCOL", "CURLE_FAILED_INIT", "CURLE_URL_MALFORMAT", "CURLE_URL_MALFORMAT_USER", "CURLE_COULDNT_RESOLVE_PROXY", "CURLE_COULDNT_RESOLVE_HOST", "CURLE_COULDNT_CONNECT", "CURLE_FTP_WEIRD_SERVER_REPLY", "CURLE_REMOTE_ACCESS_DENIED", "CURLE_FTP_WEIRD_PASS_REPLY", "CURLE_FTP_WEIRD_PASV_REPLY", "CURLE_FTP_WEIRD_227_FORMAT", "CURLE_FTP_CANT_GET_HOST", "CURLE_FTP_COULDNT_SET_TYPE", "CURLE_PARTIAL_FILE", "CURLE_FTP_COULDNT_RETR_FILE", "CURLE_QUOTE_ERROR", "CURLE_HTTP_RETURNED_ERROR", "CURLE_WRITE_ERROR", "CURLE_UPLOAD_FAILED", "CURLE_READ_ERROR", "CURLE_OUT_OF_MEMORY", "CURLE_OPERATION_TIMEDOUT", "CURLE_FTP_PORT_FAILED", "CURLE_FTP_COULDNT_USE_REST", "CURLE_RANGE_ERROR", "CURLE_HTTP_POST_ERROR", "CURLE_SSL_CONNECT_ERROR", "CURLE_BAD_DOWNLOAD_RESUME", "CURLE_FILE_COULDNT_READ_FILE", "CURLE_LDAP_CANNOT_BIND", "CURLE_LDAP_SEARCH_FAILED", "CURLE_FUNCTION_NOT_FOUND", "CURLE_ABORTED_BY_CALLBACK", "CURLE_BAD_FUNCTION_ARGUMENT", "CURLE_INTERFACE_FAILED", "CURLE_TOO_MANY_REDIRECTS", "CURLE_UNKNOWN_TELNET_OPTION", "CURLE_TELNET_OPTION_SYNTAX", "CURLE_PEER_FAILED_VERIFICATION", "CURLE_GOT_NOTHING", "CURLE_SSL_ENGINE_NOTFOUND", "CURLE_SSL_ENGINE_SETFAILED", "CURLE_SEND_ERROR", "CURLE_RECV_ERROR", "CURLE_SSL_CERTPROBLEM", "CURLE_SSL_CIPHER", "CURLE_SSL_CACERT", "CURLE_BAD_CONTENT_ENCODING", "CURLE_LDAP_INVALID_URL", "CURLE_FILESIZE_EXCEEDED", "CURLE_USE_SSL_FAILED", "CURLE_SEND_FAIL_REWIND", "CURLE_SSL_ENGINE_INITFAILED", "CURLE_LOGIN_DENIED", "CURLE_TFTP_NOTFOUND", "CURLE_TFTP_PERM", "CURLE_REMOTE_DISK_FULL", "CURLE_TFTP_ILLEGAL", "CURLE_TFTP_UNKNOWNID", "CURLE_REMOTE_FILE_EXISTS", "CURLE_TFTP_NOSUCHUSER", "CURLE_CONV_FAILED", "CURLE_CONV_REQD", "CURLE_SSL_CACERT_BADFILE", "CURLE_REMOTE_FILE_NOT_FOUND", "CURLE_SSH", "CURLE_SSL_SHUTDOWN_FAILED", "CURLE_AGAIN", "CURLE_SSL_CRL_BADFILE", "CURLE_SSL_ISSUER_ERROR", "CURLE_FTP_PRET_FAILED", "CURLE_RTSP_CSEQ_ERROR", "CURLE_RTSP_SESSION_ERROR", "CURLE_FTP_BAD_FILE_LIST", "CURLE_CHUNK_FAILED", "CURLE_NO_CONNECTION_AVAILABLE", "CURLE_SSL_PINNEDPUBKEYNOTMATCH", "CURLE_SSL_INVALIDCERTSTATUS"};

#endif

