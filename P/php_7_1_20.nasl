#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111231);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-14851", "CVE-2018-14883", "CVE-2018-15132");

  script_name(english:"PHP 7.1.x < 7.1.20 exif_thumbnail_extract() DoS");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.1.x prior to 7.1.20. It is, therefore, affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-7.php#7.1.20");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=76423");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.1.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
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

# Check that it is the correct version of PHP
if (version =~ "^7(\.1)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^7\.1\.") audit(AUDIT_NOT_DETECT, "PHP version 7.1.x", port);

fix = "7.1.20";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
