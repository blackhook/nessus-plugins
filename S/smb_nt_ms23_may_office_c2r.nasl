#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(175393);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/12");

  script_cve_id("CVE-2023-29333", "CVE-2023-29344");

  script_name(english:"Security Updates for Microsoft Office Products C2R (May 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update. It is, therefore, affected by the following
vulnerabilities:

  - A remote code execution vulnerability. (CVE-2023-29344)

  - A denial of service vulnerability. (CVE-2023-29333)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#may-09-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dd4c7fe");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-05';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16327.20248','channel':'Current'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16227.20318','channel':'Enterprise Deferred','channel_version':'2303'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16130.20500','channel':'Enterprise Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16130.20500','channel':'First Release for Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15601.20660','channel':'Deferred','channel_version':'2208'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14931.21000','channel':'Deferred'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.16327.20248','channel':'2021 Retail'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.16327.20248','channel':'2019 Retail'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16327.20248','channel':'2016 Retail'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.14332.20503','channel':'LTSC 2021'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10398.20008','channel':'2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Office'
);
