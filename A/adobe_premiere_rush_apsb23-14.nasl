#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171557);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id("CVE-2023-22234", "CVE-2023-22244");
  script_xref(name:"IAVA", value:"2023-A-0098");

  script_name(english:"Adobe Premiere Rush <= 2.6 Arbitrary Code Execution (APSB23-14)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Premiere Rush installed on the remote Windows host is affected by multiple arbitrary code execution vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Rush installed on the remote Windows host is version less than or equal to 2.6. It is,
therefore, affected by multiple arbitrary code execution vulnerabilities due to a stack-based buffer overflow and a
use after free condition.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/premiere_rush/apsb23-14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5053ee9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Rush version 2.7 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_rush");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "adobe_premiere_rush_installed.nasl", "macosx_adobe_premiere_rush_installed.nbin");
  script_require_keys("installed_sw/Adobe Premiere Rush");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Adobe Premiere Rush');

var constraints = [
  # Windows version numbers have a build number in the 4th position
  { 'fixed_version' : '2.6.0.99999', 'fixed_display' : '2.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
