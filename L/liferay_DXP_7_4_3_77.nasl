#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177740);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-35029", "CVE-2023-35030");
  script_xref(name:"IAVA", value:"2023-A-0312");

  script_name(english:"Liferay DXP  7.4.13.70 < x < 7.4.13.77 Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The detected install of Liferay DXP is between 7.4.13.70 and 7.4.13.76. 
It is therefore affected by multiple vulnerabilities:

  - Cross-site request forgery (CSRF) vulnerability in the Layout module's SEO configuration 
  in Liferay Portal 7.4.13.70 through 7.4.13.76 allows remote attackers to execute arbitrary 
  code in the scripting console via the _com_liferay_layout_admin_web_portlet_
  GroupPagesPortlet_backURL parameter. (CVE-2023-35030)

  - Open redirect vulnerability in the Layout module's SEO configuration in Liferay Portal 
  7.4.13.70 through 7.4.13.76, to redirect users to arbitrary external URLs via the 
  _com_liferay_layout_admin_web_portlet_GroupPagesPortlet_backURL parameter. CVE-2023-35029)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2023-35030
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6164959a");
  # https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2023-35029
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2b8f2b8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 7.4.13.77 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:liferay_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detection.nbin");
  script_require_keys("installed_sw/Liferay DXP");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'Liferay DXP');

var constraints = [ {'min_version': '7.4.13.70' , 'fixed_version': '7.4.13.77' , 'fixed_display': '7.4 update 77' } ];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE,
  flags:{'xsrf':TRUE}
);
