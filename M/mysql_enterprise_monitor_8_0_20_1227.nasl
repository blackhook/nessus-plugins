#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138039);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-17563");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MySQL Enterprise Monitor 4.0.11.x < 4.0.12.5341 / 8.0.18.x < 8.0.20.1227(Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a session fixation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor application running on the remote host is 
4.0.11.x prior to 4.0.12.5341 or 8.0.18.x prior to 8.0.20.1227. It is, therefore, affected by a session fixation
vulnerability. An unauthenticated, remote attacker could exploit this to steal the session of a valid user and perform
actions in their name.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b68cc3b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 4.0.12.5341 / 8.0.20.1227 or later as referenced in the April Oracle CPU");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17563");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:18443);
app_info = vcf::get_app_info(app:'MySQL Enterprise Monitor', port:port, webapp:true);

constraints = [
  { 'min_version' : '4.0.11', 'fixed_version' : '4.0.12.5341' },
  { 'min_version' : '8.0.18', 'fixed_version' : '8.0.20.1227' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
