#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135709);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/23");

  script_cve_id("CVE-2019-18196");

  script_name(english:"TeamViewer Windows Service DLL Sideloading Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected
by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A Dll sideloading vulnerability exist in 
TeamViewer 11 prior to 11.0.214397, TeamViewer 12 prior to 12.0.214399, 
TeamViewer 13 prior to 13.2.36216,TeamViewer 11 prior to 11.0.214397, on Windows could allow an attacker
to perform code execution via service restart where the DLL was previously installed with administrative 
privileges in the target system.");
  # https://community.teamviewer.com/t5/Announcements/Security-bulletin-CVE-2019-18196/td-p/74564
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc009a84");
  script_set_attribute(attribute:"solution", value:
"Upgrade for Teamviewer 11, upgrade to 11.0.214397 or later. For Teamviewer 12, upgrade to 12.0.214399 or later.
For Teamviewer 13, upgrade to 13.2.36216 or later. For Teamviewer 14, upgrade to 14.7.1965. 
Alternatively, apply the workarounds outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(426);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed", "installed_sw/TeamViewer/");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'TeamViewer');

constraints = [
  { "min_version" : "11.0.0", "fixed_version" : "11.0.214397" },
  { "min_version" : "12.0.0", "fixed_version" : "12.0.214399" },
  { "min_version" : "13.0.0", "fixed_version" : "13.2.36216" },
  { "min_version" : "14.0.0", "fixed_version" : "14.7.1965" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
