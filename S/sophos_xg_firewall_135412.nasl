#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136175);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-12271");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0039");

  script_name(english:"Sophos XG Firewall - SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote Sophos XG Firewall is affected by an SQL Injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"A SQL injection (SQLi) vulnerability exists in SFOS 17.0, 17.1, 17.5, and 18.0 before 2020-04-25 due to improper
validation of user-supplied input. An unauthenticated, remote attacker can exploit this to inject or manipulate SQL
queries in the back-end database, resulting in the disclosure or manipulation of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://community.sophos.com/kb/en-us/135412");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sophos:xg_firewall_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sophos_xg_firewall_detect.nbin");
  script_require_keys("installed_sw/Sophos XG Firewall", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('http.inc');

app_name = 'Sophos XG Firewall';
port = get_http_port(default:443);
app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);
version = app_info['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  {'min_version':'0.0', 'max_version':'17.0.9.217', 'fixed_display':'A vulnerable version was found'},
  {'min_version':'17.1', 'max_version':'17.1.4.254', 'fixed_display':'A vulnerable version was found'},
  {'min_version':'17.5', 'max_version':'17.5.8.539', 'fixed_display':'A vulnerable version was found'},
  {'min_version':'18.0', 'max_version':'18.0.0.113', 'fixed_display':'A vulnerable version was found'}
];

report =
  '\n  Detected on port       : ' + port +
  '\n  Installed version      : ' + version +
  '\n  vulnerable version was installed.\n';
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
