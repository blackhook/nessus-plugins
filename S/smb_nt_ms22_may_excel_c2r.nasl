##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(162046);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2022-29110");
  script_xref(name:"IAVA", value:"2022-A-0193-S");

  script_name(english:"Security Updates for Microsoft Excel Products C2R (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update. It is, therefore, affected by the following vulnerability:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-29110)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29110");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-05';

var constraints = [
    {'fixed_version':'16.0.15128.20224','channel': '2016 Retail'},
    {'fixed_version':'16.0.15128.20224','channel': 'Current'},
    {'fixed_version':'16.0.15028.20248','channel': 'Enterprise Deferred','channel_version': '2203'},
    {'fixed_version':'16.0.14931.20392','channel': 'Enterprise Deferred'},
    {'fixed_version':'16.0.14931.20392','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.14326.20962','channel': 'Deferred','channel_version': '2108'},
    {'fixed_version':'16.0.13801.21334','channel': 'Deferred'},
    {'fixed_version':'16.0.12527.22145','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.15128.20224','channel': '2021 Retail'},
    {'fixed_version':'16.0.15128.20224','channel': '2019 Retail'},
    {'fixed_version':'16.0.14332.20303','channel': 'LTSC 2021'},
    {'fixed_version':'16.0.10386.20017','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Excel'
);
