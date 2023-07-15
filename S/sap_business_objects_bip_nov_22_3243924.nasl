#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168363);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id("CVE-2022-41203");
  script_xref(name:"IAVA", value:"2023-A-0018");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform (Central Management Console and BI Launchpad) Insecure Deserialization");

  script_set_attribute(attribute:"synopsis", value:
"SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by insecure deserialization vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is prior to
4.2 SP9 P11, 4.3 SP2 P7 or 4.3 SP3. It is, therefore, affected by insecure deserialization vulnerability. In some 
workflow of SAP BusinessObjects BI Platform (Central Management Console and BI LaunchPad), an authenticated attacker 
with low privileges can intercept a serialized object in the parameters and substitute with malicious serialized one, 
which leads to deserialization of untrusted data vulnerability. This could highly compromise the Confidentiality, 
Integrity, and Availability of the system.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3243924");
  script_set_attribute(attribute:"solution", value:
"See vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41203");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version': '14.2', 'fixed_version' : '14.2.9.4411', 'fixed_display': '4.2 SP009 001100'},
  { 'min_version': '14.3', 'fixed_version' : '14.3.2.4385', 'fixed_display': '4.3 SP002 000700 / 4.3 SP003 000000'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
