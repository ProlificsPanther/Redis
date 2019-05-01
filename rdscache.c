#define SM_SCCSID	"@(#)rdscache.c	77.9 18/10/05 18:40:33"

/*************************************/
/*  Copyright  (C)  2018             */
/*          by                       */
/*  Prolifics, Incorporated          */
/*  New York, New York               */
/*  All Rights Reserved              */
/*  Printed in U.S.A.                */
/*  Confidential, Unpublished        */
/*  Property of  Prolifics, Inc.     */
/*************************************/

#include "smdefs.h"
#include "hiredis.h"
#include "hircluster.h"

/* This source file is provided as-is, and Prolifics makes no claims or
 * guarantees as to its fitness for use in a Production application.
 *
 * You may redistriubute this file and makee changes to it, provided that
 * you leave in this notice as well as the copyright notice shown above.
 *
 * This sample source file is meant to illustrate the implementation of
 * hook functions for use with Panther Web's external cache mechanism.
 * The present implementation uses Redis for the external cache, and
 * requires the hiredis-vip client software for compiling and linking.
 *
 * Panther Web's external cache mechanism works as follows:
 *
 * When the option, "ExternalCache," is set to 1 in the [Prolifics Web]
 * section of the INI file, a set of C functions are invoked to handle
 * the web state caching:
 *
 * int   web_cache_startup()
 * int   web_cache_shutdown()
 * char *web_cache_get_id()
 * int   web_cache_set(char *id, void *val, int len)
 * void *web_cache_get(char *id, int *plen)
 * int   web_cache_remove(char *id)
 * int   web_cache_clean(int age_in_minutes)
 *
 * The jserver calls these functions using pointers to them that must be
 * present on the PROTOTYPED FUNCTIONS list for the specific function names
 * mentioned above.  For convenience, the present source file installs the
 * hook functions in its initialization function, web_redis_init(), which
 * should be called from jweb.c.  Therefore, the code to install the hook
 * functions does not need to be added to funclist.c.  Only the more modest
 * change to jweb.c needs to be made.
 */

/* Panther Web undocumented functions that are not in a public header file */
#ifdef NO_WEB_APPNAME	/* for testing in prodev/prorun */
#define WEB_APPNAME	"panther"
#define emsg(s)		(sm_emsg(s))
#define log_msg(s)	(sm_emsg(s))
#else
/* alternative to sm_web_log_error */
void * sm_ReportError	PROTO((char *, char *, ...));
char * sm_web_appname	PROTO((void)); /* Gets the web application name */
#define WEB_APPNAME	(sm_web_appname())
#define emsg(s)		(sm_ReportError("External Cache",s))
#define log_msg(s)	(sm_ReportError("External Cache",s))
#endif	/* NO_WEB_APPNAME */

/* Severity levels for message function */
#define CACHE_ERROR	0 /* default */
#define CACHE_WARN	1
#define CACHE_DEBUG	2

#ifndef NODEBUG
#define debug_message(f,s)	(message(2,f,s))
#else
#define debug_message(f,s)
#endif

#define error_message(f,s)	(message(0,f,s))
#define warn_message(f,s)	(message(1,f,s))

#define MAX_KEY_LENGTH	100

/* Since Redis works with string values, we use the following functions
 * to encode Panther Web's cache as a string and to decode it back to binary
 */
long sm_encode64len	PROTO((long)); /* buffer length for base64 encoding */
long sm_decode64len	PROTO((long)); /* buffer length for base64 decoding */
long sm_encode64	PROTO((char *, long long, char *, long));
long sm_decode64	PROTO((char *, long, char *, long));

/* THE FOLLOWING FUNCTIONS ARE IN THIE MODULE */

/* These are hook functions called by Panther Web, and must conform to
 * the interfaces defined by Panther Web.
 */
static int	web_redis_startup		PROTO((void));
static int	web_redis_shutdown		PROTO((void));
static char *	web_redis_get_id		PROTO((void));
static int	web_redis_set			PROTO((char *, void *, int));
static void *	web_redis_get			PROTO((char *, int *));
static int	web_redis_remove		PROTO((char *));
static int	web_redis_clean			PROTO((int));

/* Convenience declaration for use in error handling */
typedef enum
{
	WEB_CACHE_STARTUP,
	WEB_CACHE_SHUTDOWN,
	WEB_CACHE_GET_ID,
	WEB_CACHE_SET,
	WEB_CACHE_GET,
	WEB_CACHE_REMOVE,
	WEB_CACHE_CLEAN
}
	fnc_id;

/* Both redisContext and redisClusterContext begin with the same
 * two members.  Therefor, we'll use the following type to store
 * the pointer to either, since we need only access err and errstr
 * those two members directly.
 */
typedef struct rContext {
	int err;
	char errstr[128];
} rContext;

/* Helper functions */
static void *	rCommand		PROTO((rContext *, const char *, ...));
static void	message			PROTO((int, fnc_id, char *));

/* Static variables; This is fine, because the jserver is single threaded. */
static rContext *c;		/* pointer to the context for the connection */
static int uses_cluster;	/* 1 if cluster connection; 0 otherwise      */
static int expire_time = 7200;	/* default for Panther Web in seconds        */
static int redisLogLevel;


/*
NAME

	web_redis_init

SYNOPSIS

	retcode = web_redis_init ()
	int retcode;

DESCRIPTION

	web_redis_init should be called in jweb.c to install the web cache
	hook functions that will be called by the jserver.  This is not
	one of those hook functions itself.

	Note that we used different names for the actual functions defined
	in this file than the names given to the jserver as strings with
	which to lookup the function pointers.  Perhaps this technique 
	could be used to link in more than one caching implementation,
	allowing an application configuration mechanism to select which
	implementation to actually initialize at startup.

RETURNS

	always 0
*/

int
web_redis_init NOPARMS(())
{
	static SMCONST struct fnc_data cachefuncs[] =
	{
		SM_INTFNC ("web_cache_startup()",	web_redis_startup),
		SM_INTFNC ("web_cache_shutdown()",	web_redis_shutdown),
		SM_STRFNC ("web_cache_get_id()",	web_redis_get_id),
		SM_INTFNC ("web_cache_set(s,s,i)",	web_redis_set),
		SM_ZROFNC ("web_cache_get(s,i)",	web_redis_get),
		SM_INTFNC ("web_cache_remove(s)",	web_redis_remove),
		SM_INTFNC ("web_cache_clean(i)",	web_redis_clean)
	};
	static int pcount = sizeof (cachefuncs) / sizeof (struct fnc_data);

	/* Try for a unique seed for each jserver - but no guarantee. */
	unsigned int seed = (unsigned int)clock() ^ (unsigned int)getpid();

	srand(seed);

	sm_install(PROTO_FUNC, (struct fnc_data *)cachefuncs, &pcount);

	return 0;
}

/*
NAME

	web_redis_startup

SYNOPSIS

	retcode = web_redis_startup ()
	int retcode;

DESCRIPTION

	This function is installed as "web_cache_startup()".  The jserver
	calls it so that you can perform cache specific initialization,
	such as acquiring a connection to a database that will be reused.

	The present function first checks for the RedisCluster option in
	the environment.  RedisCluster can be set to a string like,
	"127.0.0.1:6379,127.0.0.1:6380".  Variables can be set in the
	environment by specifying them in the [Environment] section of
	the INI file.

	If RedisCluster is set, its value is used to try to get a connection
	to the cluster.  If not, then the environment variables RedisHost
	and RedisPort are used to try to get a non-cluster connection.
	RedisHost is for just a single host name or IP address, and
	RedisPort is for a single port number on that host on which the
	Redis server is listening.

	If a connection is established, we next check for RedisPassword
	in the environment.  If it is set we send it with the AUTH command
	to Redis.

	If there is no error, we next check if RedisDatabase is ser in the
	environment.  If it is set, then we send its value to Redis using
	the SELECT command.

	In case of an error, a Redis error code is returned if one is
	available from the Redis client software.  For any other error,
	the Redis error code, REDIS_ERR_OTHER, is returned.  The jserver
	does not do anything with the return code, so it doesn't matter
	if it is Redis specific.

RETURNS

	A redis error code;
	Or 0 for no error
*/

static int
web_redis_startup NOPARMS(())
{
	int err = REDIS_ERR_OTHER;
	char *redisHost = getenv("RedisHost");
	char *redisPort = getenv("RedisPort");
	char *redisDatabase = getenv("RedisDatabase");
	char *redisCluster = getenv("RedisCluster");
	char *redisPassword = getenv("RedisPassword");
	char *redisExpireTime = getenv("RedisExpireTime"); /* seconds */
	char *logLevel = getenv("RedisLogLevel");

	debug_message(WEB_CACHE_STARTUP, "Entry");

	if (redisExpireTime)
		expire_time = atoi(redisExpireTime);
		
	if (logLevel)
		redisLogLevel = atoi(logLevel);

	if (redisCluster == NULL && (redisHost == NULL || redisPort == NULL))
	{
		error_message(WEB_CACHE_STARTUP,
			"RedisCluster is NULL, and "
			"either RedisHost or RedisPort is NULL, or both are "
			"NULL");
		debug_message(WEB_CACHE_STARTUP, "Exit");
		return err;
	}

	/* It is unexpected, but in case c is non-NULL, we should choose 
	 * to do something reasonable. If it is pointing at invalid
	 * memory, we may crash if we use it or even free it.  Otherwise,
	 * we'll leak memory.  Either is bad, but a crash is easier to fix,
	 * and has less hazardous side effects, so we'll go with that.
	 */
	if (c)
		web_redis_shutdown();

	if (redisCluster)
	{
		c = (rContext *)redisClusterContextInit();
		redisClusterSetOptionAddNodes((redisClusterContext *)c,
							redisCluster);
		redisClusterConnect2((redisClusterContext *)c);
		uses_cluster = 1;
	}
	else
	{
		c = (rContext *)redisConnect(redisHost, atoi(redisPort));
		uses_cluster = 0;
	}

	if (c)
	{
		err = c->err;
		if (err)
			error_message(WEB_CACHE_STARTUP, c->errstr);

		if (!err && redisPassword)
		{
			redisReply *reply;

			/* We seem to have to do authentication after
			 * making a successful connection.
			 */
			reply = rCommand(c, "AUTH %s", redisPassword);

			if (c->err)
			{
				err = c->err;
				error_message(WEB_CACHE_STARTUP, c->errstr);
			}
			else if (reply && reply->type == REDIS_REPLY_ERROR)
			{
				err = REDIS_ERR_OTHER;
				if (reply->str)
				{
					error_message(
						WEB_CACHE_STARTUP, reply->str);
				}
			}
			freeReplyObject(reply);
		}

		if (!err && redisDatabase)
		{
			redisReply *reply;

			/* The documentation for Redis says that SELECT
			 * isn't supported for clusters, but we won't check.
			 * We'll just let this code fail if we've connected
			 * to a cluster, if that is the correct behavior.
			 */
			reply = rCommand(c, "SELECT %s", redisDatabase);

			if (c->err)
			{
				err = c->err;
				error_message(WEB_CACHE_STARTUP, c->errstr);
			}
			else if (reply && reply->type == REDIS_REPLY_ERROR)
			{
				err = REDIS_ERR_OTHER;
				if (reply->str)
				{
					error_message(
						WEB_CACHE_STARTUP, reply->str);
				}
			}
			freeReplyObject(reply);
		}

		if (err)
		{
			if (uses_cluster)
				redisClusterFree((redisClusterContext *)c);
			else
				redisFree((redisContext *)c);
			c = (rContext *)0;
		}
	}
	else
	{
		error_message(WEB_CACHE_STARTUP,
			"Connetion failed with a NULL context returned.");
	}
	debug_message(WEB_CACHE_STARTUP, "Exit");

	return err;
}

/*
NAME

	web_redis_shutdown

SYNOPSIS

	retcode = web_redis_shutdown ()
	int retcode;

DESCRIPTION

	This function is installed as "web_cache_shutdown()".  The jserver
	calls this function to allow for the closing of any persistent
	connections to the cache or other cleanup to be performed.  The
	return code is ignored by the jserver.

RETURNS

	A redis error code;
	Or 0 for no error
*/
static int
web_redis_shutdown NOPARMS(())
{
	debug_message(WEB_CACHE_SHUTDOWN, "Entry");
	if (!c)
	{
		error_message(WEB_CACHE_SHUTDOWN, "Context is NULL");
		debug_message(WEB_CACHE_SHUTDOWN, "Exit");
		return REDIS_ERR_OTHER;
	}

	if (uses_cluster)
		redisClusterFree((redisClusterContext *)c);
	else
		redisFree((redisContext *)c);

	c = (rContext *)0;
	debug_message(WEB_CACHE_SHUTDOWN, "Exit");

	return 0;
}

/*
NAME

	web_redis_get_id

SYNOPSIS

	id = web_redis_get_id ()
	char *id;

DESCRIPTION

	This function is installed as "web_cache_get_id()".  The jserver
	calls this function to get a unique id.  This id will be used as
	the leading part of the webid for the current web request, and it
	will be used as the keyname for which Panther will store its state
	information into the cache as a single blob value.

	web_redis_get_id() must return a unique key name for use in the
	cache, and it should be difficult for a hacker to guess.  We
	allocate a buffer, using sm_fmalloc(), to hold the return value,
	because the jserver will free this buffer with sm_ffree() when it
	is no longer needed.  We always put an id into the buffer, even
	if some portion of the code to generate the id fails.

	The value returned must be unique across all jservers.  For
	uniqueness, we use the	web application name in combination with
	a value returned by the Redis INCR command.

	Note that INCR is atomic in returning an incremented value.  However,
	DB consistency is not guaranteed, especially if clusters are used.
	We may do better with the counter here is we if we save its most
	recent value in a static, and always make sure that reply->integer
	is greater than the saved value.  If not, we might increment the
	count by some large amount to avoid colistions with counters
	produced by other jservers.

	Nevertheless, the use of a random number in the id as well as a
	timestamp, not only makes the webid difficult to guess, but also
	reduces the changes of creating dupicate webids in different
	jservers, even if the counter value is occasionally duplicated.

	The webid used by the jserver is actually not the id returned by
	this function.  The jserver tacks onto the end of this id its own
	timestamp, random number, and possibly additional information, in
	order to construct the final webid that is sent back to the client,
	and available to the application as the webid property of the
	application.

RETURNS

	A pointer to an sm_fmalloc'd buffer containing the id;
	NULL if the id cannot be generated due to some failure
*/

static char *
web_redis_get_id NOPARMS(())
{
	char *id;
	char *name = WEB_APPNAME;
	time_t now = time((time_t *)0);
	static unsigned long seq;
	unsigned long prev_seq = seq;
	redisReply *reply = NULL;
	unsigned long count = 0L;

	debug_message(WEB_CACHE_GET_ID, "Entry");

	id = sm_fmalloc(MAX_KEY_LENGTH * sizeof(char));

	if (!id)
	{
		error_message(WEB_CACHE_GET_ID, "Malloc failure for cache id");
		return id;
	}
	else if (!c)
	{
		error_message(WEB_CACHE_GET_ID, "Context is NULL");
		sm_ffree(id);
		return NULL;
	}
	else
	{
		reply = rCommand(c, "INCR %s", name);

		if (c->err && c->errstr)
		{
			error_message(WEB_CACHE_GET_ID, c->errstr);
			sm_ffree(id);
			if (reply)
				freeReplyObject(reply);
			return NULL;
		}
	}

	if (reply && reply->type == REDIS_REPLY_ERROR && reply->str)
	{
		error_message(WEB_CACHE_GET_ID, reply->str);

		/* try to recover */
		web_redis_remove(name);

		count = (unsigned long)reply->integer;
		sm_ffree(id);
		freeReplyObject(reply);
		return NULL;
	}
	else if (!reply || reply->type != REDIS_REPLY_INTEGER)
	{
		error_message(WEB_CACHE_GET_ID, "Redis command error for INCR");
		sm_ffree(id);
		if (reply)
			freeReplyObject(reply);
		return NULL;
	}
	else /* success */
	{
		count = (unsigned long)reply->integer;
	}
	freeReplyObject(reply);

	do
	{
		seq += (unsigned long)rand();
	}
	while (prev_seq == seq);

	/* count and name should guarantee uniqueness; now and seq
	 * make it difficult to guess.
	 */

#ifdef SM_WIN64
	sprintf(id, "%s-%llu-%lu-%lu", name, now, seq, count);
#else
	sprintf(id, "%s-%lu-%lu-%lu", name, now, seq, count);
#endif

	if (redisLogLevel > CACHE_DEBUG)
	{
		char buf[MAX_KEY_LENGTH + 20];

		sprintf(buf, "id=%s", id);
		debug_message(WEB_CACHE_GET_ID, buf);
	}
	debug_message(WEB_CACHE_GET_ID, "Exit");

	return id;
}

/*
NAME

	web_redis_set

SYNOPSIS

	retcode = web_redis_set (id, val, len)
	int retcode;
	char *id;
	void *val;
	int len;

DESCRIPTION

	This function is installed as "web_cache_set(s,s,i)".  The jserver
	calls this function to save its state information for the present
	web request before cleaning up and returning data to the client.

	The first paramter is an id that was previously obtained by the
	jserver by calling web_cache_get_id().  It will be used as the
	key name for the single cache entry that will be made by this
	function.

	The second parameter is a pointer to a buffer containing the state
	information in some custom binary format used by the jserver.  The
	buffer will contain all web saved globals, bundles, etc., as one
	blob.

	The final parameter is the length of the data stored in the blob
	pointed to by val.

	Since Redis works natively with stings for values, the present
	function performs a base64 encoding of the blob in order to store
	a NULL terminated ASCII string into the Redis cache.

RETURNS

	A redis error code;
	Or 0 for no error
*/

static int
web_redis_set PARMS((id, val, len))
PARM(char *id)
PARM(void *val)
LASTPARM(int len)
{
	long enclen = sm_encode64len(len);
	char *encbuf = NULL;
	long length = -1L;
	redisReply *reply;
		
	debug_message(WEB_CACHE_SET, "Entry");

	if (redisLogLevel > CACHE_DEBUG)
	{
		char buf[255];

		sprintf(buf, "id=%s, val=%p, len=%d", id, val, len);
		debug_message(WEB_CACHE_GET_ID, buf);
	}

	if (!c)
		error_message(WEB_CACHE_SET, "Context is NULL");
	else if (!id)
		error_message(WEB_CACHE_SET, "id (keyname) is NULL");
	else if (enclen <= 0L)
		error_message(WEB_CACHE_SET, "invalid data length");
	else
		encbuf = (char *)sm_fmalloc((size_t)enclen + 1);

	if (encbuf)
	{
 		length = sm_encode64(val, len, encbuf, enclen);	
		if (length == -1L)
			error_message(WEB_CACHE_SET, "base64 encoding failed");
	}

	if (length == -1L)
	{
		sm_ffree(encbuf);
		debug_message(WEB_CACHE_SET, "Exit");
		return REDIS_ERR_OTHER;
	}

	encbuf[enclen] = 0L;	/* make sure it is NULL terminated */

	reply = rCommand(c, "SETEX %s %d %s", id, expire_time, encbuf);

	if (c->err && c->errstr)
		error_message(WEB_CACHE_SET, c->errstr);
	else if (reply && reply->type == REDIS_REPLY_ERROR && reply->str)
		error_message(WEB_CACHE_SET, reply->str);

	sm_ffree(encbuf);

	/* We don't need the reply object, so we free it.
	 * hiredis.c shows that freeReplyObject checks for the argument
	 * being NULL argument.
	 */
	freeReplyObject(reply);
	debug_message(WEB_CACHE_SET, "Exit");

	return c->err;
}

/*
NAME

	web_redis_get

SYNOPSIS

	val = web_redis_get (id, plen)
	char *val;
	char *id;
	int *plen;

DESCRIPTION

	This function is installed as "web_cache_get(s,i)".  It is of no
	consequence that the prototype indicates an 'i' for 'int', though
	the function is actually passed a pointer to an int.  The jserver
	uses the name and prototype only to look up the function in its
	function list.  It, nevertheless, calls the function by its
	pointer on that funciton list using a pointer to an int as the
	second argument.

	This function retrieves the blob of state information that had 
	previously been assigned to the key name specified by the id 
	parameter.  If non-NULL, as is expected, the plen parameter is
	filled with length of the blob of data that is returned from
	this function.

	Since Redis works natively with stings for values, it is expected
	that the state information had been stored as a base64 encoded
	string.  The present function decodes this string after retrieving
	it from the Redis cache.

RETURNS

	A pointer to a blob of session state information for the id;
	the length of the blob data in plen
*/

static void *
web_redis_get PARMS((id, plen))
PARM(char *id)
LASTPARM(int *plen)
{
	long declen = 0L;
	char *val = NULL;
	redisReply *reply;
	long enclen;
	char *decbuf = NULL;
	long length;

	debug_message(WEB_CACHE_GET, "Entry");

	if (redisLogLevel > CACHE_DEBUG)
	{
		char buf[255];

		sprintf(buf, "id=%s, plen=%p", id, plen);
		debug_message(WEB_CACHE_GET_ID, buf);
	}

	if (!c)
	{
		error_message(WEB_CACHE_GET, "Context is NULL");
		debug_message(WEB_CACHE_GET, "Exit");
		return NULL;
	}
	else if (!id)
	{
		error_message(WEB_CACHE_GET, "id (keyname) is NULL");
		debug_message(WEB_CACHE_GET, "Exit");
		return NULL;
	}
	else if (!plen)
	{
		/* This will be only a warning.  We'll still retrieve the
		 * data.  This allows NULL terminated string values to be
		 * for testing this function directly from JPL.
		 */
		error_message(WEB_CACHE_GET,
			"Warning: return pointer for data length is NULL");
	}

	if (plen)
		*plen = 0L;

	reply = rCommand(c, "GET %s", id);

	if (c->err && c->errstr)
	{
		error_message(WEB_CACHE_GET, c->errstr);
		debug_message(WEB_CACHE_GET, "Exit");
		return NULL;
	}
	else if (reply && reply->type == REDIS_REPLY_ERROR && reply->str)
	{
		error_message(WEB_CACHE_GET, reply->str);
		debug_message(WEB_CACHE_GET, "Exit");
		return NULL;
	}
	else if (!reply || !reply->str)
	{
		error_message(WEB_CACHE_GET, "Command error for GET");
		debug_message(WEB_CACHE_GET, "Exit");
		return NULL;
	}

	enclen = (long)strlen(reply->str);
	if (enclen > 0L)
	{
		declen = sm_decode64len(enclen);
		if (declen <= 0L)
			error_message(WEB_CACHE_GET, "invalid decode length");
	}
	else
		error_message(WEB_CACHE_GET, "invalid length for reply string");

	if (declen > 0L)
	{
		decbuf = (char *)sm_fmalloc((size_t)declen);
		if (!decbuf)
		{
			error_message(
				WEB_CACHE_GET, "memory allocation failure");
		}
	}

	if (decbuf)
	{
		length = sm_decode64(decbuf, declen, reply->str, enclen);
		if (length == -1L)
			error_message(WEB_CACHE_GET, "base64 decoding failed");
	}

	if (plen)
		*plen = (int)length;

	if (length != -1L)
		val = decbuf;

	freeReplyObject(reply);
	debug_message(WEB_CACHE_GET, "Exit");

	return val;
}

/*
NAME

	web_redis_remove

SYNOPSIS

	retcode = web_redis_remove (id)
	int retcode;
	char *id;

DESCRIPTION

	This function is installed as "web_cache_remove(s)".  The jserver
	calls this function to remove the cache entry for the session state
	information corrsponding to the id given as the parameter.

	The jserver ignores the return code.

RETURNS

	A redis error code;
	Or 0 for no error
*/

static int
web_redis_remove PARMS((id))
LASTPARM(char *id)
{
	redisReply *reply = NULL;
	int other_err = 0;

	debug_message(WEB_CACHE_REMOVE, "Entry");

	if (redisLogLevel > CACHE_DEBUG)
	{
		char buf[255];

		sprintf(buf, "id=%s", id);
		debug_message(WEB_CACHE_GET_ID, buf);
	}

	if (!c)
	{
		error_message(WEB_CACHE_REMOVE, "Context is NULL");
		debug_message(WEB_CACHE_REMOVE, "Exit");
		return REDIS_ERR_OTHER;
	}

	reply = rCommand(c, "DEL %s", id);

	if (c->err)
	{
		error_message(WEB_CACHE_REMOVE,
			c->errstr ? c->errstr : "Command error for DEL");
	}
	else if (!reply)
	{
		other_err = REDIS_ERR_OTHER;
		error_message(WEB_CACHE_REMOVE, "Command error for DEL");
	}
	else if (reply->type == REDIS_REPLY_ERROR && reply->str)
	{
		other_err = REDIS_ERR_OTHER;
		error_message(WEB_CACHE_REMOVE, reply->str);
	}

	freeReplyObject(reply);
	debug_message(WEB_CACHE_REMOVE, "Exit");
  
	return c->err ? c->err : other_err;
}

/*
NAME

	web_redis_clean

SYNOPSIS

	retcode = web_redis_clean (age)
	int retcode;
	int age;

DESCRIPTION

	This function is installed as "web_cache_clean(i)".  The jserver
	calls this function to remove any cache cache entry older that the
	given age in seconds.  The age is derived from the value for
	ExpireTime in the INI file.

	For the present implmentation for Redis, we tell Redis the expire
	time when setting each key.  It is more efficient than finding
	all of the keys and checking their ages.

	Therfore, we don't need to delete expired keys in this function.
	We might have used this function to set the expire time that will
	be used on future calls to web_cache_set(), but the first call to
	web_cache_set() can occur before the first call to web_cache_clean().
	Therefore, this function is simply a no-op, and ExpireTime in the
	[Prolifics Web] section of the INI file is not used at all by the
	present external web cache implementation.  Rather, we use a
	custom RedisExpireTime variable in the [Environment] section of
	the INI file.  This variable is assigned a value in seconds, rather
	than minutes. The default is 7200.

	Note that jserver ignores the return code from this function.

RETURNS

	Always returns 0
*/
static int
web_redis_clean PARMS((unused_age))
LASTPARM(int unused_age)
{
	debug_message(WEB_CACHE_CLEAN, "Entry");
	unused_age = unused_age;
	warn_message(WEB_CACHE_CLEAN, "This function is a no-op. "
		"Redis server will perform clean-up of expired entries "
		"automatically.");
	debug_message(WEB_CACHE_CLEAN, "Exit");

	return 0;
}

/*
NAME

	rCommand

SYNOPSIS

	retval = rCommand (c, format, ...)
	void *retval;
	rContext c;
	const char *format;

DESCRIPTION

	rCommand is a helper function to wrap calls to either redisCommand
	or redisCustomerCommand.  The first paramter is an rContext*, which
	is a type defined in this file that can be used to hold either a
	redisContext* or a redisClusterContext*.  The second paramter is
	the format paramter that is the same as for redisCommand and
	redisCustomerCommand.  Following that is a variable argument list,
	the same as for redisCommand and redisCustomerCommand.

	Note that we actually call redisClustervCommand or redisvCommand,
	rather than redisCustomerCommand or redisCommand, respectively.

RETURNS

	generally a redisReply* containing a reply
*/
static void *
rCommand PARMS((rContext *, const char *))
PARM(rContext *c)
PARM(const char *format)
VARPARM()
{
	va_list args;
	void *reply = NULL;

	va_start(args, format);

	if (uses_cluster)
	{
		reply = redisClustervCommand(
				(redisClusterContext *)c, format, args);
	}
	else
	{
		reply = redisvCommand((redisContext *)c, format, args);
	}
	va_end(args);

	return reply;
}

/*
NAME

	message

SYNOPSIS

	void message (level, id, msg)
	int level;
	fnc_id id;
	char *msg;

DESCRIPTION

	This is a helper function for logging error messages.  The first
	parameter is the severity level. Currently, only CACHE_DEBUG and
	CACHE_ERROR are supported.

	The second paramter is an id for the function in which the error
	occurred, not a web id.  The type of this parameter, fnc_id, is
	defined in this file as an enum.  We then use the value of that
	enum to look up the name of the function within a static array
	of pointers defined in the present function.  From this function
	name and the msg parameter, we construct the message to be logged.
*/
static void
message PARMS((level, id, msg))
PARM(int level)
PARM(fnc_id id)
LASTPARM(char *msg)
{
	static SMCONST char *fnc_names[] = {
		"web_redis_startup",	/* WEB_CACHE_STARTUP	*/
		"web_redis_shutdown",	/* WEB_CACHE_SHUTDOWN	*/
		"web_redis_get_id",	/* WEB_CACHE_GET_ID	*/
		"web_redis_set",	/* WEB_CACHE_SET	*/
		"web_redis_get",	/* WEB_CACHE_GET	*/
		"web_redis_remove",	/* WEB_CACHE_REMOVE	*/
		"web_redis_clean"	/* WEB_CACHE_CLEAN	*/
	};

	static char msgbuf[1000];	/* c->errstr is at most 127 chars */

	if (level > redisLogLevel)
		return;

	if (level == CACHE_ERROR)
	{
		sprintf(msgbuf, "ERROR: %s - ", fnc_names[id]);
		strncat(msgbuf, msg, sizeof(msgbuf) - 50);
		emsg(msgbuf);
	}
	else if	(level == CACHE_WARN)
	{
		sprintf(msgbuf, "WARNING: %s - ", fnc_names[id]);
		strncat(msgbuf, msg, sizeof(msgbuf) - 50);
		log_msg(msgbuf);
	}
	else	/* CACHE_DEBUG or higher */
	{
		sprintf(msgbuf, "DEBUG: %s - ", fnc_names[id]);
		strncat(msgbuf, msg, sizeof(msgbuf) - 50);
		log_msg(msgbuf);
	}
}

