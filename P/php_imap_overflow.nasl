#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10628);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(6557);

  script_name(english:"PHP < 4.0.4 IMAP Module imap_open() Function Overflow");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on this host.");
  script_set_attribute(attribute:"description", value:
"A version of PHP that is older than 4.0.4 is installed on this host.

There is a buffer overflow condition in the IMAP module of this version
that could allow an attacker to execute arbitrary commands with the 
privileges of the web server, if this server is serving a webmail 
interface.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Mar/40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^4\.0\.[0-3]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.0.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
