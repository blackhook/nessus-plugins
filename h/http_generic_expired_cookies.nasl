#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if(description)
{
  script_id(100669);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/20");

  script_name(english:"Web Application Cookies Are Expired");

  script_set_attribute(attribute:"synopsis", value:
"HTTP cookies have an 'Expires' attribute that is set with a past date
or time.");
  script_set_attribute(attribute:"description", value:
"The remote web application sets various cookies throughout a user's
unauthenticated and authenticated session. However, Nessus has
detected that one or more of the cookies have an 'Expires' attribute
that is set with a past date or time, meaning that these cookies will
be removed by the browser.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6265");
  script_set_attribute(attribute:"solution", value:
"Each cookie should be carefully reviewed to determine if it contains
sensitive data or is relied upon for a security decision.

If needed, set an expiration date in the future so the cookie will
persist or remove the Expires cookie attribute altogether to convert
the cookie to a session cookie.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');

load_cookiejar(jar:'expired');

var port = get_http_port(default: 80, embedded: TRUE);
var keys_l = get_http_cookie_keys(name_re: ".*", port: port);
var report = "";
var h_cookies = 0;

if (empty_or_null(keys_l)) exit(1, 'expired CookieJar is empty or returns null.');

foreach k (keys_l)
{
  var h = get_http_cookie_from_key(k);
  report = report +
    '\nName : ' + h['name'] +
    '\nPath : ' + h['path'] +
    '\nValue : ' + h['value'] +
    '\nDomain : ' + h['domain'] +
    '\nVersion : ' + h['version'] +
    '\nExpires : ' + h['expires'] +
    '\nComment : ' + h['comment'] +
    '\nSecure : ' + h['secure'] +
    '\nHttponly : ' + h['httponly'] +
    '\nPort : ' + h['port'] +
    '\n\n';

  h_cookies+=1;
}

if (strlen(report) > 0)
{
  if (h_cookies > 1) s = 's are';
  else s = ' is';

  report = '\nThe following cookie' + s + ' expired :\n' + report;
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}
else audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
