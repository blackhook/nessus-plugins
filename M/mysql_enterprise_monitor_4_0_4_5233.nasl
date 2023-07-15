#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111600);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2016-9878", "CVE-2017-3737");
  script_bugtraq_id(95072, 102103);

  script_name(english:"MySQL Enterprise Monitor 3.3.x < 3.3.9.3339 / 3.4.x < 3.4.7.4296 / 4.0.x < 4.0.4.5233 Multiple Vulnerabilities (April 2018 CPU)");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor 
application running on the remote host is 3.3.x prior to 3.3.9.3339 
or 3.4.x prior to 3.4.7.4296 or 4.0.x prior to 4.0.4.5233. It is, 
therefore, affected by multiple vulnerabilities as noted in the April 
2018 Critical Patch Update advisory. Please consult the CVRF details 
for the applicable CVEs for additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.3.9.3339 / 3.4.7.4296 / 
4.0.4.5233 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "MySQL Enterprise Monitor";
port = get_http_port(default:18443);

app_info = vcf::get_app_info(app:app, port:port, webapp:true);

constraints = [

  { "min_version" : "3.3", "fixed_version" : "3.3.9.3339" },
  { "min_version" : "3.4", "fixed_version" : "3.4.7.4296" },
  { "min_version" : "4.0", "fixed_version" : "4.0.4.5233" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
