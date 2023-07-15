#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166121);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-35296", "CVE-2022-39015");
  script_xref(name:"IAVA", value:"2022-A-0406");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform 4.2 < 4.2 SP9 P10 / 4.3 < 4.3 SP2 P7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is prior to
4.2 SP9 P10, 4.3 SP2 P7 or 4.3 SP3. It is, therefore, affected by multiple vulnerabilities:

 - Under certain conditions, BOE AdminTools/BOE SDK allows an authenticated attacker to access information
   which would otherwise be restricted. (CVE-2022-39015)

 - Under certain conditions, the SAP BusinessObjects Business Intelligence Platform Version Management System
   exposes sensitive information to a remote actor with high privileges. (CVE-2022-35296)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3233226");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3239296");
  script_set_attribute(attribute:"solution", value:
"See vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_business_objects_intelligence_platform_win_installed.nbin");
  script_require_keys("installed_sw/SAP BusinessObjects Business Intelligence Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
constraints = [
  # Translation not available at time of release so using next build number after previous patch
  { 'min_version': '14.2', 'fixed_version' : '14.2.9.4303', 'fixed_display': '4.2 SP009 001000'},
  { 'min_version': '14.3', 'fixed_version' : '14.3.2.4344', 'fixed_display': '4.3 SP002 000700 / 4.3 SP003 000000'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
