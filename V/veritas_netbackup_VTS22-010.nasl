#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174321);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2022-42306", "CVE-2022-42308");
  script_xref(name:"IAVA", value:"2023-A-0181");

  script_name(english:"Veritas NetBackup < 8.3 Multiple Vulnerabilities (VTS22-010)");

  script_set_attribute(attribute:"synopsis", value:
"A back-up management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Veritas NetBackup application installed on the remote Windows host is prior to 8.3 and may be missing a vendor-supplied
security hotfix. It is, therefore, affected by multiple vulnerabilities:

  - An attacker with local access can send a crafted packet to pbx_exchange during registration and cause a
    NULL pointer exception, effectively crashing the pbx_exchange process. (CVE-2022-42308)

  - An attacker with local access can delete arbitrary files by leveraging a path traversal in the pbx_exchange
    registration code. (CVE-2022-42306)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS22-010");
  script_set_attribute(attribute:"solution", value:
"Apply the Emergency Engineering Binary (EEB) / security hotfix as
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_netbackup_installed.nbin");
  script_require_keys("installed_sw/NetBackup");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NetBackup', win_local:TRUE);

if(report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

# Flex does not appear supported by our detection
var install_type = tolower(app_info['Install type']);
if ('client' >!< install_type && 'server' >!< install_type)
  audit(AUDIT_HOST_NOT, 'affected');

var constraints = [
  { 'min_version' : '0', 'fixed_version' : '8.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
