#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131735);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/22");

  script_cve_id("CVE-2019-6477");
  script_xref(name:"IAVA", value:"2019-A-0434-S");

  script_name(english:"ISC BIND 9.11.0 / 9.11.x < 9.11.13 / 9.11.x < 9.11.13-S1 / 9.12.x < 9.12.5-P2 / 9.14.x < 9.14.8 / 9.15 / 9.15.x < 9.15.6 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in ISC BIND 9 due to TCP Client issues. 
An unauthenticated, remote attacker can exploit this issue, via DNS Request, to cause 
the device to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2019-6477");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2019-6477");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate version of BIND.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'equal' : '9.11.0' },
  { 'min_version' : '9.11.6-P1', 'max_version' : '9.11.12' , 'fixed_version' : '9.11.13'},
  { 'min_version' : '9.11.5-S6', 'max_version' : '9.11.12-S1', 'fixed_version' : '9.11.13-S1'},
  { 'min_version' : '9.12.4-P1', 'max_version' : '9.12.4-P2', 'fixed_version' : '9.12.5'},
  { 'min_version' : '9.14.1', 'max_version' : '9.14.7', 'fixed_version' : '9.14.8' },
  { 'min_version' : '9.15.0', 'max_version' : '9.15.5', 'fixed_version' : '9.15.6' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
