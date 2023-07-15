#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# This script is written by Shruti

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15911);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1219");
  script_bugtraq_id(11818);

  script_name(english:"paFileDB sessions Directory Admin Hashed Password Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure issue.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of paFileDB
is vulnerable to an attack that would allow the attacker to view the
password hash of user accounts, including an administrator account, by
making a direct request to the application's 'sessions' directory. This
could allow an attacker to perform brute-force attacks on the password
hash and gain access to account information.

The vulnerability exists only when session-based authentication is
performed, which is not the default.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=110245123927025&w=2");
  script_set_attribute(attribute:"solution", value:
"Set log_errors=on and display_errors=off in php.ini");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_arena:pafiledb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("pafiledb_detect.nasl");
  script_require_keys("www/pafiledb");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 ver = matches[1];
 if (ver =~ "^([0-2]|3\.0|3\.1( *b|$))") security_warning(port);
}
