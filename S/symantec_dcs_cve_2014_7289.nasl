#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81549);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-7289");
  script_bugtraq_id(72092);

  script_name(english:"Symantec Data Center Security Server SQLi (SYM15-001)");
  script_summary(english:"Attempts to exploit the SQL Injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Symantec Data Center Security Server running on the remote
host is affected by a SQL injection vulnerability in the
'/sis-ui/authenticate' script on the web console interface. A remote
attacker, using a crafted HTTP request, can exploit this to execute
SQL queries, allowing the disclosure or modification of arbitrary
data.");
  # https://support.symantec.com/en_US/article.SYMSA1311.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0364a137");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Data Center Security version 6.0 MP1, and apply
the protection policy modifications described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7289");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_dcs_console_interface_detect.nbin", "http_version.nasl");
  script_require_keys("installed_sw/Symantec Data Center Security Server Console");
  script_require_ports("Services/www", 4443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("charset_func.inc");

function unicode (str)
{
  local_var retval, i;
  retval = '';
  for (i=0; i<strlen(str); i++)
    retval += str[i] + '\x00';
  return retval;
}

appname = 'Symantec Data Center Security Server Console';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:4443);

get_single_install(app_name:appname, port:port);

req_head = 'Data-Format=text/plain\n'+
           'Data-Type=properties\n'+
           'Data-Length=';

req_args = unicode(str:'ai=1\r\nun=\'\r\npwd=\r\n');
req = req_head + strlen(req_args) + '\n\n' + req_args + '\nEOF_FLAG\n';

res = http_send_recv3(method       : "POST",
                      port         : port,
                      add_headers  : make_array("AppFire-Format-Version", "1.0",
                                                "AppFire-Charset"       , "UTF-16LE",
                                                "Content-Type"          , "application/x-appfire"),
                      item         : "/sis-ui/authenticate",
                      data         : req,
                      exit_on_fail : TRUE);

if(tolower(res[1]) =~ "content-type\s*:\s*application/x-appfire" &&
   "java.sql.SQLException: Invalid SQL statement or JDBC escape, terminating ''' not found." >< get_ascii_printable(string:res[2]))
{
  set_kb_item(name:'www/' + port + '/SQLInjection', value:TRUE);
  if(report_verbosity > 0)
  {
    http_req = http_last_sent_request();

    for (i=0; i<strlen(http_req); i++)
      if(!is_ascii_printable(http_req[i])) http_req[i] = '.';

    report = '\nNessus was able to verify the vulnerability exists with the following HTTP request :\n' +
             '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
             http_req +
             '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/sis-ui/'));
