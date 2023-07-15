#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14356);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1724");
  script_bugtraq_id(10974);

  script_name(english:"PHP-Fusion Database Backup Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is prone to an
information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to obtain a dump of the remote database.  PHP-Fusion
has the ability to create database backups and store them on the web
server, in the directory '/fusion_admin/db_backups/'.  Since there is no
access control on that directory, an attacker may guess the name of a
backup database and download it.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/372034");
  script_set_attribute(attribute:"solution", value:
"Use a .htaccess file or the equivalent to control access to files in
the backup directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "php_fusion_detect.nasl", "no404.nasl");
  script_require_keys("www/php_fusion", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);
if (get_kb_item("www/no404/"+port)) exit(0);

install = get_install_from_kb(
  appname      : "php_fusion",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
ver = install["ver"];

if ( ver =~ "^([0-3][.,]|4[.,]00)" )
{
  w = http_send_recv3(
    method  : "GET",
    item    : dir + "/fusion_admin/db_backups/",
    port    : port,
    exit_on_fail : TRUE
  );
  r = w[2];
  if ( egrep(pattern:"^HTTP/.* 200 .*", string:r) )
  {
    security_warning(port);
  }
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), ver);
