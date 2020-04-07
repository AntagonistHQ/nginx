
/*
 * Copyright (C) Sander Hoentjen
 * Copyright (C) Antagonist B.V.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_sieve_module.h>


static ngx_int_t ngx_mail_sieve_authenticate(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_sieve_capability(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_sieve_starttls(ngx_mail_session_t *s,
    ngx_connection_t *c);


static u_char  sieve_ok[] = "OK \"completed\"" CRLF;
static u_char  sieve_next[] = "OK" CRLF;
static u_char  sieve_plain_next[] = "\"\"" CRLF;
static u_char  sieve_ready[] = "OK \"SIEVE ready.\"" CRLF;
static u_char  sieve_username[] = "\"VXNlcm5hbWU6\"" CRLF;
static u_char  sieve_password[] = "\"UGFzc3dvcmQ6\"" CRLF;
static u_char  sieve_invalid_command[] = "NO \"Error in MANAGESIEVE command: Unknown command.\"" CRLF;


void
ngx_mail_sieve_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char                    *p;
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_mail_sieve_capability(s, c);
    ngx_str_set(&s->out, sieve_ready);
    if (s->tagged_line.len < s->text.len + s->out.len) {
        s->tagged_line.len = s->text.len + s->out.len;
        s->tagged_line.data = ngx_pnalloc(c->pool, s->tagged_line.len);
        if (s->tagged_line.data == NULL) {
            ngx_mail_close_connection(c);
            return;
        }
    }

    p = s->tagged_line.data;

    if (s->text.len) {
        p = ngx_cpymem(p, s->text.data, s->text.len);
    }

    ngx_memcpy(p, s->out.data, s->out.len);

    s->out.len = s->text.len + s->out.len;
    s->out.data = s->tagged_line.data;

    c->read->handler = ngx_mail_sieve_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_mail_close_connection(c);
    }

    ngx_mail_send(c->write);
}


void
ngx_mail_sieve_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_sieve_srv_conf_t  *mscf;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
            == NGX_ERROR)
        {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        mscf = ngx_mail_get_module_srv_conf(s, ngx_mail_sieve_module);

        s->buffer = ngx_create_temp_buf(c->pool, mscf->client_buffer_size);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = s->mail_state == ngx_sieve_starttls ? ngx_sieve_starttls : ngx_sieve_start;
    c->read->handler = ngx_mail_sieve_auth_state;

    ngx_mail_sieve_auth_state(rev);
}


void
ngx_mail_sieve_auth_state(ngx_event_t *rev)
{
    u_char              *p, *dst, *src, *end;
    ngx_str_t           *arg;
    ngx_int_t            rc;
    ngx_uint_t           i;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "sieve send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    if (s->mail_state == ngx_sieve_starttls) {
        rc = NGX_OK;
    } else {
        rc = ngx_mail_read_command(s, c);
    }

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    s->text.len = 0;
    ngx_str_set(&s->out, sieve_ok);

    if (rc == NGX_OK) {

        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "sieve auth command: %i",
                       s->command);

        if (s->backslash) {

            arg = s->args.elts;

            for (i = 0; i < s->args.nelts; i++) {
                dst = arg[i].data;
                end = dst + arg[i].len;

                for (src = dst; src < end; dst++) {
                    *dst = *src;
                    if (*src++ == '\\') {
                        *dst = *src++;
                    }
                }

                arg[i].len = dst - arg[i].data;
            }

            s->backslash = 0;
        }

        switch (s->mail_state) {

        case ngx_sieve_start:

            switch (s->command) {

            case NGX_SIEVE_AUTHENTICATE:
                rc = ngx_mail_sieve_authenticate(s, c);
                break;

            case NGX_SIEVE_CAPABILITY:
                rc = ngx_mail_sieve_capability(s, c);
                break;

            case NGX_SIEVE_LOGOUT:
                s->quit = 1;
                break;

            case NGX_SIEVE_NOOP:
                break;

            case NGX_SIEVE_STARTTLS:
                rc = ngx_mail_sieve_starttls(s, c);
                s->mail_state = ngx_sieve_starttls;
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_sieve_starttls:
	    rc = ngx_mail_sieve_capability(s, c);
	    s->mail_state = ngx_sieve_start;
	    break;

        case ngx_sieve_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c, 0);

            ngx_str_set(&s->out, sieve_password);
            s->mail_state = ngx_sieve_auth_login_password;

            break;

        case ngx_sieve_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_sieve_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_sieve_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;

        case ngx_sieve_auth_external:
            rc = ngx_mail_auth_external(s, c, 0);
            break;
        }

    } else if (rc == NGX_SIEVE_NEXT) {
        ngx_str_set(&s->out, sieve_next);
    }

    switch (rc) {

    case NGX_DONE:
        ngx_mail_auth(s, c);
        return;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        s->state = 0;
        ngx_str_set(&s->out, sieve_invalid_command);
        s->mail_state = ngx_sieve_start;
        break;
    }


    if (s->tagged_line.len < s->text.len + s->out.len) {
        s->tagged_line.len = s->text.len + s->out.len;
        s->tagged_line.data = ngx_pnalloc(c->pool, s->tagged_line.len);
        if (s->tagged_line.data == NULL) {
            ngx_mail_close_connection(c);
            return;
        }
    }

    p = s->tagged_line.data;

    if (s->text.len) {
        p = ngx_cpymem(p, s->text.data, s->text.len);
    }

    ngx_memcpy(p, s->out.data, s->out.len);

    s->out.len = s->text.len + s->out.len;
    s->out.data = s->tagged_line.data;

    if (rc != NGX_SIEVE_NEXT) {
        s->args.nelts = 0;

        if (s->state) {
            s->arg_start = s->buffer->start;
            s->buffer->pos = s->arg_start;
            s->buffer->last = s->arg_start;

        } else {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
        }
    }

    ngx_mail_send(c->write);
}


static ngx_int_t
ngx_mail_sieve_authenticate(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_sieve_srv_conf_t  *mscf;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    mscf = ngx_mail_get_module_srv_conf(s, ngx_mail_sieve_module);

    rc = ngx_mail_auth_parse(s, c);

    switch (rc) {

    case NGX_MAIL_AUTH_LOGIN:

        ngx_str_set(&s->out, sieve_username);
        s->mail_state = ngx_sieve_auth_login_username;

        return NGX_OK;

    case NGX_MAIL_AUTH_LOGIN_USERNAME:

        ngx_str_set(&s->out, sieve_password);
        s->mail_state = ngx_sieve_auth_login_password;

        return ngx_mail_auth_login_username(s, c, 1);

    case NGX_MAIL_AUTH_PLAIN:

        ngx_str_set(&s->out, sieve_plain_next);
        s->mail_state = ngx_sieve_auth_plain;

        return NGX_OK;

    case NGX_MAIL_AUTH_CRAM_MD5:

        if (!(mscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

            if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ngx_mail_auth_cram_md5_salt(s, c, "", 0, 1) == NGX_OK) {
            s->mail_state = ngx_sieve_auth_cram_md5;
            return NGX_OK;
        }

        return NGX_ERROR;

    case NGX_MAIL_AUTH_EXTERNAL:

        if (!(mscf->auth_methods & NGX_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        ngx_str_set(&s->out, sieve_username);
        s->mail_state = ngx_sieve_auth_external;

        return NGX_OK;
    }

    return rc;
}


static ngx_int_t
ngx_mail_sieve_capability(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_sieve_srv_conf_t  *mscf;

    mscf = ngx_mail_get_module_srv_conf(s, ngx_mail_sieve_module);

#if (NGX_MAIL_SSL)

    if (c->ssl == NULL) {
        ngx_mail_ssl_conf_t  *sslcf;

        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
            s->text = mscf->starttls_capability;
            return NGX_OK;
        }

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
            s->text = mscf->starttls_only_capability;
            return NGX_OK;
        }
    }
#endif

    s->text = mscf->capability;

    return NGX_OK;
}


static ngx_int_t
ngx_mail_sieve_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
{
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
        if (sslcf->starttls) {
            c->read->handler = ngx_mail_starttls_handler;
            return NGX_OK;
        }
    }

#endif

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}
