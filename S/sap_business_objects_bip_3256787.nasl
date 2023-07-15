#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171439);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id("CVE-2023-24530");
  script_xref(name:"IAVA", value:"2023-A-0076");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform Unrestricted File Upload (3256787)");

  script_set_attribute(attribute:"synopsis", value:
"SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host may be affected by an unrestricted file upload vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is prior to
4.2 SP9 P12, 4.3 SP2 P9, 4.3 SP3 P1 or 4.3 SP4. It may, therefore, be affected by an unrestricted file upload
vulnerability in the Central Management Console (CMC). A remote attacker, authenticated with administrator
privileges may be able to upload malicious code that would be executed by the application, completely compromising
the application.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3256787");
  script_set_attribute(attribute:"solution", value:
"See vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24530");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_business_objects_intelligence_platform_win_installed.nbin");
  script_require_keys("installed_sw/SAP BusinessObjects Business Intelligence Platform", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# There is a workaround that we can't check
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
var constraints = [
  # 4.2 SP9 P12, 4.3 SP2 P9, 4.3 SP3 p1, or 4.3 SP4
  { 'min_version': '14.2', 'fixed_version' : '14.2.9.4473', 'fixed_display': '4.2 SP009 001200'},
  { 'min_version': '14.3', 'fixed_version' : '14.3.2.4469', 'fixed_display': '4.3 SP002 000900'},
  { 'min_version': '14.3.3', 'fixed_version' : '14.3.3.4496', 'fixed_display': '4.3 SP003 000100 / 4.3 SP004 000000'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
