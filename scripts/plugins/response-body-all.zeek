@load ../__load__

module ResponseBody;

hook ResponseBody::include(hostname: string, url: string) &priority = 10
    {
    break;
    }
