#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159761);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-27671");
  script_xref(name:"IAVA", value:"2022-A-0150");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform XSRF (3130497)");

  script_set_attribute(attribute:"synopsis", value:
"SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by a
cross site request forgery (XSRF) vulnerability. An XSRF token visible in the URL may lead to information disclosure.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3130497");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/15");

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

var app_info = vcf::get_app_info(app:'SAP BusinessObjects Business Intelligence Platform', win_local:TRUE);

# https://launchpad.support.sap.com/#/notes/0001602088 for translations
# Only 14.2 Patch 9.6 published now, so set this as the max_version
var constraints = [
  { 'min_version': '14.2',   'max_version'   : '14.2.9.4130', 'fixed_display': '4.2 SP009 000700'},
  { 'min_version': '14.3',   'fixed_version' : '14.3.1.4142', 'fixed_display': '4.3 SP001 001100'},
  { 'min_version': '14.3.2', 'fixed_version' : '14.3.2.4169', 'fixed_display': '4.3 SP002 000200 / 4.3 SP003'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
