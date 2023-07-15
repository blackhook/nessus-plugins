#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106103);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-3736", "CVE-2017-12617");
  script_bugtraq_id(100954, 101666, 102495);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"MySQL Enterprise Monitor 3.3.x < 3.3.7.3306 / 3.4.x < 3.4.5.4248 / 4.0.x < 4.0.2.5168 Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
application running on the remote host is 3.3.x prior to 3.3.7.3306,
3.4.x prior to 3.4.5.4248, or 4.0.x prior to 4.0.2.5168.
It is, therefore, affected by multiple vulnerabilities as
noted in the January 2018 Critical Patch Update advisory. Please
consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.3.7.3306/ 3.4.5.4248 /
4.0.2.5168 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 Tenable Network Security, Inc.");

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
          "^4.0": "4.0.2.5168",
          "^3.4": "3.4.5.4248",
          "^3.3": "3.3.7.3306"
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
