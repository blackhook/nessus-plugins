##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146444);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-21444");
  script_xref(name:"IAVA", value:"2021-A-0084");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform Clickjacking (2935791)");

  script_set_attribute(attribute:"synopsis", value:
"SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by
a vulnerability. SAP Business Objects BI Platform, versions - 410, 420, 430, allows multiple X-Frame-Options headers
entries in the response headers, which may not be predictably treated by all user agents. This could, as a result,
nullify the added X-Frame-Options header leading to Clickjacking attack.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=568460543");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/2935791");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects_business_intelligence_platform");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_business_objects_intelligence_platform_win_installed.nbin");
  script_require_keys("installed_sw/SAP BusinessObjects Business Intelligence Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
constraints = [
  { 'min_version': '14.1', 'fixed_version' : '14.1.12.3612', 'fixed_display': '4.1 SP012 000800'},
  { 'min_version': '14.2', 'fixed_version' : '14.2.7.3592', 'fixed_display': '4.2 SP007 001200'},
  { 'min_version': '14.2.8', 'fixed_version' : '14.2.8.3550', 'fixed_display': '4.2 SP008 000300 / 4.2 SP009 000000'},
  { 'min_version': '14.3', 'fixed_version' : '14.3.0.3569', 'fixed_display': '4.3 SP000 000100 / 4.3 SP000 000500'},
  { 'min_version': '14.3.1', 'fixed_version' : '14.3.1.3701', 'fixed_display': '4.3 SP001 000000'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
