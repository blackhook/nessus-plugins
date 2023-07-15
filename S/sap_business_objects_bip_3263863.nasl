#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171437);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2023-23856");
  script_xref(name:"IAVA", value:"2023-A-0076");

  script_name(english:"SAP BusinessObjects Business Intelligence Platform XSS (3263863)");

  script_set_attribute(attribute:"synopsis", value:
"SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is affected by a cross-site scripting vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SAP BusinessObjects Business Intelligence Platform installed on the remote Windows host is prior to
4.3 SP2 P9, 4.3 SP3 P1 or 4.3 SP4. It is, therefore, affected by a cross-site scripting (XSS) vulnerability. In SAP
BusinessObjects Business Intelligence Web Intelligence user interface, some calls return JSON with the wrong content
type in the header of the response. As a result, a custom application that calls directly the JSP of Web Intelligence
DHTML may be vulnerable to XSS attacks.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3263863");
  script_set_attribute(attribute:"solution", value:
"See vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23856");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

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
var constraints = [
  # 4.3 SP2 P9, 4.3 SP3 p1, or 4.3 SP4
  { 'min_version': '14.3', 'fixed_version' : '14.3.2.4469', 'fixed_display': '4.3 SP002 000900'},
  { 'min_version': '14.3.3', 'fixed_version' : '14.3.3.4496', 'fixed_display': '4.3 SP003 000100 / 4.3 SP004 000000'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
