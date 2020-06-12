module ResponseBody;

export {
    ## Hook to include http response body
    global include: hook(hostname: string, url: string);
    
    ## Hook to exclude http response body
    global exclude: hook(hostname: string, url: string);
}

@load base/protocols/http/main

module HTTP;

export {
    redef record Info += {
       response_body: string &log &optional;
       ## add response_time
       end_time: time &optional;
       start_time: time &optional;
       response_time: double &log &optional;
    };

    ## Flag that indicates whether to hook reply bodies.
    const hook_reply_bodies = T &redef;

    ## Do not buffer more than this amount of bytes per HTTP message.
    const max_body_size = 4096;
}

## Users write a handler for this event to process the current HTTP body.

event http_begin_entity(c: connection, is_orig: bool)
    {

    if ( ! c$http?$host )
        return;  

    if ( ! hook ResponseBody::exclude(c$http$host, c$http$uri) )
        return;

    if ( hook ResponseBody::include(c$http$host, c$http$uri) )
        return;

    if ( (is_orig) || (! is_orig && ! hook_reply_bodies) )
        return;

    c$http$response_body = "";
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! c$http?$response_body )
        return;

    c$http$response_body += data;
    if ( |c$http$response_body| > max_body_size )
        {
        c$http$response_body = c$http$response_body[0:max_body_size] + "...";
        }
    }
