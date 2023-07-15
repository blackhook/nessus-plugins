#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22316);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-4673");
  script_bugtraq_id(19908, 19910);

  script_name(english:"PHP-Fusion extract() Global Variable Overwriting");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
variable overwriting flaw.");
  script_set_attribute(attribute:"description", value:
"The version of PHP-Fusion on the remote host supports registering
variables from user-supplied input in the event that PHP's
'register_globals' setting is disabled, which is the default in
current versions of PHP.  Unfortunately, the way that this has been
implemented in the version on the remote host does not restrict the
variables that can be registered.  Consequently, an unauthenticated,
remote attacker can leverage this flaw to launch various attacks
against the affected application.");
  # https://web.archive.org/web/20120402151936/http://retrogod.altervista.org/phpfusion_6-01-4_xpl.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27bfc08c");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/445480/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.php-fusion.co.uk/infusions/news/news.php?readmore=353");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.01.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
  script_require_keys("www/php_fusion", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(
  appname      : "php_fusion",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];

# Try to exploit the flaw to generate a SQL error.
host = rand() % 255 + "." + rand() % 255 + "." + rand() % 255 + ".111" +
  "'/**/UNION+SELECT+" + SCRIPT_NAME + "--";

r = http_send_recv3(
  method     : "GET",
  port       : port,
  item       : dir + "/news.php?" + "_SERVER[REMOTE_ADDR]=" + host,
  exit_on_fail : TRUE
);

# There's a problem if we see an error w/ the first 3 octets of our "host".
if (string("syntax to use near '", host - strstr(host, ".111"), "''") >< r[2])
{
  security_note(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port));
