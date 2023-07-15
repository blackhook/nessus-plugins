#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled 2018/09/07. Duplicate Plugin
#

include("compat.inc");

if (description)
{
  script_id(117340);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
      "CVE-2018-14883",
      "CVE-2018-14851",
      "CVE-2018-15132"
      );
  script_bugtraq_id(
      105205
      );

  script_name(english:"PHP < 5.6.37 or 7.2.x < 7.2.8 Multiple Vulnerabilities (Deprecated)");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to prior coverage");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.2.8");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.37");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:'cvss_score_source', value:"CVE-2018-14883");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

exit(0, "This plugin has been deprecated.");

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

fix = NULL;

if (version =~ "^7\.[0-2].*") fix = "7.2.8";
else if (version =~ "^[1-5].*") fix = "5.6.37";
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

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
