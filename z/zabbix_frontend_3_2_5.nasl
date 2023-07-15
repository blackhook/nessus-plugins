#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100615);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-2824", "CVE-2017-2825");
  script_bugtraq_id(98083, 98094);

  script_name(english:"Zabbix 2.0.x < 2.0.21 / 2.2.x < 2.2.18 / 3.0.x < 3.0.9 / 3.2.x < 3.2.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Zabbix
running on the remote host is 2.0.x prior to 2.0.21, 2.2.x prior to
2.2.18, 3.0.x prior to 3.0.9, or 3.2.x prior to 3.2.5. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    trapper command functionality due to improper handling
    of trapper packets. An unauthenticated, remote attacker
    can exploit this, via a specially crafted set of trapper
    packets, to inject arbitrary commands and execute
    arbitrary code. (CVE-2017-2824 / TALOS-2017-0325)

  - A security bypass vulnerability exists in the trapper
    command functionality due to improper handling of
    trapper packets. A man-in-the-middle (MitM) attacker can
    exploit this, via a specially crafted trapper packet, to
    bypass database security checks and write arbitrary data
    to the database. (CVE-2017-2825 / TALOS-2017-0326)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://blog.talosintelligence.com/2017/04/zabbix-multiple-vulns.html");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/reports/TALOS-2017-0325/");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/reports/TALOS-2017-0326/");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-12075");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-12076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 2.0.21 / 2.2.18 / 3.0.9 / 3.2.5 or later.
Alternatively, to mitigate CVE-2017-2824, delete the three default
script entries inside the Zabbix Server database per the
TALOS-2017-0325 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2825");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("installed_sw/zabbix", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "zabbix";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (ver =~ "^2\.0\.([0-9]|[1][0-9]|20|21rc[0-9]+)($|[^0-9])")
  fix = "2.0.21";

else if (ver =~ "^2\.2\.([0-9]|1[0-7]|18rc[0-9]+)($|[^0-9])")
  fix = "2.2.18";

else if (ver =~ "^3\.0\.([0-8]|9rc[0-9]+)($|[^0-9])")
  fix = "3.0.9";

else if (ver =~ "^3\.2\.([0-4]|5rc[0-9]+)($|[^0-9])")
  fix = "3.2.5";

if (!isnull(fix))
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 2.0.21 / 2.2.18 / 3.0.9 / 3.2.5' +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zabbix", install_url, ver);
