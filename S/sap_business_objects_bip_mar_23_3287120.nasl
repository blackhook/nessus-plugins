#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172580);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2023-27271", "CVE-2023-27894", "CVE-2023-27896");
  script_xref(name:"IAVA", value:"2023-A-0130");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform Multiple Vulnerabilities (3287120)");

  script_set_attribute(attribute:"synopsis", value:
"The SAP business intelligence product installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by a
multiple vulnerabilities: 

  - SSRF, an attacker can control a malicious BOE server, forcing the application server to connect to its own 
    admintools (CVE-2023-27271)
  
  - SSRF, n attacker can control a malicious BOE server, forcing the application server to connect to its 
    own CMS (CVE-2023-27896)

  - information disclosure that allows an attacker to inject arbitrary values as CMS parameters to perform 
    lookups on the internal network which is otherwise not accessible externally. (CVE-2023-27894) 

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  # https://launchpad.support.sap.com/#/notes/3287120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81780a1c");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27894");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_business_objects_intelligence_platform_win_installed.nbin");
  script_require_keys("installed_sw/SAP BusinessObjects Business Intelligence Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
# Advisory shows SP004 but there is no info for SP004 in the above link
var constraints = [
  { 'min_version': '14.2', 'fixed_version' : '14.2.9.4527', 'fixed_display': '4.2 SP009 001300'},
  { 'min_version': '14.3', 'fixed_version' : '14.3.2.4537', 'fixed_display': '4.3 SP002 001000'},
  { 'min_version': '14.3.3', 'fixed_version' : '14.3.3.4496', 'fixed_display': '4.3 SP003 000100'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);