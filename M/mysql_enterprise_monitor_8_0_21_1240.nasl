#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138568);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1551", "CVE-2020-1967");
  script_xref(name:"IAVA", value:"2020-A-0321");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"MySQL Enterprise Monitor 4.0.x < 4.0.13.5349 / 8.0.x < 8.0.21.1240 (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a multiple vulnerabilties");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor application running on the remote host is 
4.0.x prior to 4.0.13.5349 or 8.0.x prior to 8.0.21.1240. It is, therefore, affected by multiple vulnerabilities:
  - A buffer overflow condition exists in the Montgomery squaring procedure due to unsufficient validation
  of user-supplied input. An unauthenticated, remote attacker can exploit this, to cause a denial of service
  condition or the execution of arbitrary code. (CVE-2019-1551).

  - A denial of service (DoS) vulnerability exists in the SSL_check_chain() function due to a NULL pointer
  dereference. An unauthenticated, remote attacker can exploit this issue, to cause the application 
  to stop responding (CVE-2020-1967).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpujul2020.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d433c246");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 4.0.13.5349 / 8.0.21.1240 or later as referenced in the July Oracle CPU");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:18443);
app_info = vcf::get_app_info(app:'MySQL Enterprise Monitor', port:port, webapp:true);

constraints = [
  { 'min_version' : '4.0', 'fixed_version' : '4.0.13.5349' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.21.1240' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

