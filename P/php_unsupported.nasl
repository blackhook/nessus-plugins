#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58987);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");
  script_xref(name:"IAVA", value:"0001-A-0581");

  script_name(english:"PHP Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a web application
scripting language.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of PHP on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/eol.php");
  script_set_attribute(attribute:"see_also", value:"https://wiki.php.net/rfc/releaseprocess");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PHP that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Unsupported Software");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

if (isnull(version)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "PHP", port);

# http://php.net/eol.php as ref
eos_dates = make_array(
  "^7\.4($|\.)"  , '2022/11/28',
  "^7\.3($|\.)"  , '2021/12/06', 
  "^7\.2($|\.)"  , '2020/11/30',
  "^7\.1($|\.)"  , '2019/12/01',
  "^7\.0($|\.)"  , '2019/01/10',
  "^5\.6($|\.)"  , '2018/12/31',
  "^5\.5($|\.)"  , '2016/07/21',
  "^5\.4($|\.)"  , '2015/09/03',
  "^5\.3($|\.)"  , '2014/08/14',
  "^5\.2($|\.)"  , '2011/01/06',
  "^5\.1($|\.)"  , '2006/08/24',
  "^5\.0($|\.)"  , '2005/09/05',
  "^4\.4($|\.)"  , '2008/08/07',
  "^4\.3($|\.)"  , '2005/03/31',
  "^4\.2($|\.)"  , '2002/09/06',
  "^4\.1($|\.)"  , '2002/03/12',
  "^4\.0($|\.)"  , '2001/06/23',
  "^3($|\.)"     , '2000/10/20',
  "^[0-2]($|\.)" , '2000/10/20'
);

withdrawl_announcements = make_array(
  "^7\.4($|\.)"  , 'http://php.net/supported-versions.php',
  "^7\.3($|\.)"  , 'http://php.net/supported-versions.php',
  "^7\.2($|\.)"  , 'http://php.net/supported-versions.php',
  "^7\.1($|\.)"  , 'http://php.net/supported-versions.php',
  "^7\.0($|\.)"  , 'http://php.net/supported-versions.php',
  "^5\.6($|\.)"  , 'http://php.net/supported-versions.php',
  "^5\.5($|\.)"  , 'http://php.net/supported-versions.php',
  "^5\.4($|\.)"  , 'http://php.net/supported-versions.php',
  "^5\.3($|\.)"  , 'http://php.net/eol.php',
  "^5\.2($|\.)"  , 'http://php.net/eol.php',
  "^5\.1($|\.)"  , 'http://php.net/eol.php',
  "^5\.0($|\.)"  , 'http://php.net/eol.php',
  "^4\.4($|\.)"  , 'http://php.net/eol.php',
  "^4\.3($|\.)"  , 'http://php.net/eol.php',
  "^4\.2($|\.)"  , 'http://php.net/eol.php',
  "^4\.1($|\.)"  , 'http://php.net/eol.php',
  "^4\.0($|\.)"  , 'http://php.net/eol.php',
  "^3($|\.)"     , 'http://php.net/eol.php',
  "^[0-2]($|\.)" , 'http://php.net/eol.php'
);

supported_versions = '8.0.x / 8.1.x';

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = ver[0] + "." + ver[1];

# Determine support status.
obsolete = '';
foreach v (keys(eos_dates))
{
  if (version_highlevel =~ v)
  {
    obsolete = v;
    break;
  }
}

if (obsolete)
{
  register_unsupported_product(product_name:"PHP",
                               cpe_base:"php:php", version:version);

  info =
    '\n  Source              : ' + source  +
    '\n  Installed version   : ' + version;

  if (eos_dates[v])
    info += '\n  End of support date : ' + eos_dates[v];
  if (withdrawl_announcements[v])
    info += '\n  Announcement        : ' + withdrawl_announcements[v];
  info += '\n  Supported versions  : ' + supported_versions + '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:info);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
