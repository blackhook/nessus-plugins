#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103536);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-5664", "CVE-2017-9787", "CVE-2017-10424");
  script_bugtraq_id(98888, 99562, 101381);

  script_name(english:"MySQL Enterprise Monitor 3.2.x < 3.2.9.2249 / 3.3.x < 3.3.5.3292 / 3.4.x < 3.4.3.4225 Multiple Vulnerabilities (October 2017 CPU)");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a denial
of service vulnerability in apache struts 2.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
application running on the remote host is 3.2.x prior to 3.2.9.2249,
3.3.x prior to 3.3.5.3292, or 3.4.x prior to 3.4.3.4225.
It is, therefore, affected by multiple vulnerabilities as
noted in the October 2017 Critical Patch Update advisory. Please
consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cve-2017-9805-products-3905487.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d67d494");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b8727c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.2.9.2249 / 3.3.5.3292 / 
3.4.3.4225 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10424");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:18443);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

fixes = { 
          "^3.4": "3.4.3.4225",
          "^3.3": "3.3.5.3292",
          "^3.2": "3.2.9.2249"
        };

vuln = FALSE;
fix = '';
foreach (prefix in keys(fixes))
{
  if (version =~ prefix && ver_compare(ver:version,
                                       fix:fixes[prefix],
                                       strict:FALSE) < 0)
  {
    vuln = TRUE;
    fix = fixes[prefix];
    break;
  }
}

if (vuln)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
