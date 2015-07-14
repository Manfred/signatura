#include <stdio.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <util_script.h>

#include <CommonCrypto/CommonDigest.h>

typedef enum {
  S_FAILED,
  S_OK
} verify_success;

static void signatura_write_error_message(request_rec *request, const char *message)
{
  ap_set_content_type(request, "text/plain");
  ap_rputs(message, request);
}

const static void signatura_hash(const char *input, char *result)
{
  unsigned char hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_CTX context;
  int i;

  CC_SHA256_Init(&context);
  CC_SHA256_Update(&context, input, strlen(input));
  CC_SHA256_Final(hash, &context);

  for(i = 1; i < CC_SHA256_DIGEST_LENGTH; i++)
  {
    sprintf(result + (i * 2), "%02x", hash[i]);
  }
  result[64] = 0;
}

const char * signatura_lookup_secret(request_rec *request, const char *key_id)
{
  return "so-secret";
}

static verify_success signatura_signature_valid(request_rec *request, const char *key_id, const char *expires, const char *signature)
{
  const char *secret = signatura_lookup_secret(request, key_id);

  if (secret) {

    char *concatenated = apr_palloc(request->pool, strlen(secret) + strlen(expires));

    strcpy(concatenated, secret);
    strcat(concatenated, expires);

    char *computed = apr_palloc(request->pool, CC_SHA256_DIGEST_LENGTH);
    signatura_hash(concatenated, computed);

    if (strcmp(signature, computed) == 0) {
      return S_OK;
    } else {
      signatura_write_error_message(request, "The signature you supplied and the computed signature don't match.");
      return S_FAILED;
    }

  } else {
    char *message = apr_palloc(request->pool, 1024);

    sprintf(message, "Can't find secret for the key ID `%s'", key_id);
    signatura_write_error_message(request, message);

    return S_FAILED;

  }
}

static verify_success signatura_not_expired(request_rec *request, const char *expires)
{
  long expires_as_long = atol(expires);
  long current_as_long = (long)time(NULL);

  if (expires_as_long < current_as_long) {
    signatura_write_error_message(request, "The timestamp in the `expires' request parameter is in the past.");
    return S_FAILED;
  } else {
    return S_OK;
  }
}

static verify_success signatura_request_valid(request_rec *request, const char *key_id, const char *expires, const char *signature)
{
  return (
    signatura_not_expired(request, expires) &&
    signatura_signature_valid(request, key_id, expires, signature)
  );
}

static verify_success signatura_verify_request(request_rec *request)
{
  apr_table_t *params;
  ap_args_to_table(request, &params);

  const char *key_id = apr_table_get(params, "key_id");
  const char *expires = apr_table_get(params, "expires");
  const char *signature = apr_table_get(params, "signature");

  if (!key_id) {
    signatura_write_error_message(request, "Please supply a `key_id' query parameter.");
    return S_FAILED;
  }

  if (strlen(key_id) > 512) {
    signatura_write_error_message(request, "Maximum size for the `key_id' query parameter is 512 bytes.");
    return S_FAILED;
  }

  if (!expires) {
    signatura_write_error_message(request, "Please supply an `expires' query parameter.");
    return S_FAILED;
  }

  if (strlen(expires) > 512) {
    signatura_write_error_message(request, "Maximum size for the `expires' query parameter is 512 bytes.");
    return S_FAILED;
  }

  if (!signature) {
    signatura_write_error_message(request, "Please supply a `signature' query parameter.");
    return S_FAILED;
  }

  if (strlen(signature) > 80) {
    signatura_write_error_message(request, "Maximum size for the `signaure' query parameter is 80 bytes.");
    return S_FAILED;
  }

  return signatura_request_valid(request, key_id, expires, signature);
}

static int signatura_request_handler(request_rec *request)
{
  /* We accept all requests because the handler should only be active for
   * directories which need security
   */
  if (signatura_verify_request(request)) {
    /* Don't expect a response from this module, carry on. */
    return DECLINED;
  } else {
    return HTTP_FORBIDDEN;
  }
}

static void signatura_register_hooks(apr_pool_t *pool)
{
  ap_hook_handler(signatura_request_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA signatura_module = { 
  STANDARD20_MODULE_STUFF,
  NULL,                            /* Per-directory configuration handler */
  NULL,                            /* Merge handler for per-directory configurations */
  NULL,                            /* Per-server configuration handler */
  NULL,                            /* Merge handler for per-server configurations */
  NULL,                            /* Any directives we may have for httpd */
  signatura_register_hooks         /* Our hook registering function */
};
