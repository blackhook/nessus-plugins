##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161175);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id(
    "CVE-2022-28821",
    "CVE-2022-28822",
    "CVE-2022-28823",
    "CVE-2022-28824",
    "CVE-2022-28825",
    "CVE-2022-28826",
    "CVE-2022-28827",
    "CVE-2022-28828",
    "CVE-2022-28829",
    "CVE-2022-28830"
  );
  script_xref(name:"IAVB", value:"2022-B-0013-S");

  script_name(english:"Adobe FrameMaker 2019 <= 15.0.8 (2019.0.8) / Adobe FrameMaker 2020 <= 16.0.4 (2020.0.4) Multiple Vulnerabilities (APSB22-27)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is 2019 release prior or equal to 15.0.8, or 2020
release 16.0.4. It is, therefore, potentially affected by multiple arbitrary code execution vulnerabilities due to
out-of-bounds writes as well as a memory leak vulnerability due to an out-of-bounds-read, as referenced in the APSB22-27
advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb22-27.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker version 15.0.9, 16.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28829");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

# Due to unique hotfix scenario, we are temporarily adding this paranoid condition
if (app_info['version'] =~ "(15\.0\.8|16\.0\.4)([^0-9]|$)" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Adobe FrameMaker');

var constraints = [
  { 'fixed_version' : '15.0.9', 'fixed_display' : '15.0.8 / 2019.0.8 / 2019 Update 8 (hotfix)' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.0.5', 'fixed_display' : '16.0.4 / 2020.0.4 / 2020 Update 4 (hotfix)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
