#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119681);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2017-17417");
  script_xref(name:"ZDI", value:"ZDI-17-982");
  script_xref(name:"IAVA", value:"2018-A-0408");

  script_name(english:"Quest NetVault Backup Server < 11.4.5 Process Manager Service SQL Injection Remote Code Execution Vulnerability (ZDI-17-982)");
  script_summary(english:"Checks the version of NetVault Backup Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup server is affected by an SQL injection remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Quest NetVault Backup Server running on the remote
host is prior to 11.4.5. It is, therefore, affected by an SQL
injection (SQLi) remote code execution vulnerability in the process
manager server due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this to inject or
manipulate SQL queries in the back-end database, resulting in the
disclosure or manipulation of arbitrary data and the execution of
arbitrary code.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-982/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Quest NetVault Backup Server 11.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17417");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:quest:netvault_backup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netvault_web_detect.nbin");
  script_require_keys("installed_sw/Quest NetVault Backup Server");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Quest NetVault Backup Server";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8443);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [{"fixed_version":"11.4.5"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE});
