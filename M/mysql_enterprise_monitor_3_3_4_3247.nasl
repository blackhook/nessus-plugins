#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101895);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-5647", "CVE-2017-5651");
  script_bugtraq_id(97544);

  script_name(english:"MySQL Enterprise Monitor 3.2.x < 3.2.8.2223 / 3.3.x < 3.3.4.3247 Multiple Vulnerabilities (July 2017 CPU)");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
application running on the remote host is 3.2.x prior to 3.2.8.2223 or
3.3.x prior to 3.3.4.3247. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the Apache Tomcat component in the
    handling of pipelined requests when send file processing
    is used that results in the pipelined request being lost
    when processing of the previous request has completed,
    causing responses to be sent for the wrong request. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-5647)

  - A flaw exists in the Apache Tomcat component in HTTP
    connectors when processing send files. If processing
    completed quickly, it was possible to add the processor
    to the processor cache twice, which allows the same
    processor to be used for multiple requests. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information from other sessions or
    cause unexpected errors. (CVE-2017-5651)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50229a1a");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2279658.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.2.8.2223 / 3.3.4.3247 or
later as referenced in the July 2017 Oracle Critical Patch Update
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");

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

fixes = {"^3.3": "3.3.4.3247",
         "^3.2": "3.2.8.2223"};

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
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
