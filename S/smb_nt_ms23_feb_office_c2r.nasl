#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171555);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2023-21714");
  script_xref(name:"IAVA", value:"2023-A-0082-S");

  script_name(english:"Security Updates for Microsoft Office Products C2R (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update. It is, therefore, affected by an information disclosure
vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#february-14-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba237d24");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-02';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16026.20200','channel':'Current'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15928.20282','channel':'Enterprise Deferred','channel_version':'2212'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15831.20280','channel':'Enterprise Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15601.20538','channel':'First Release for Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.15601.20538','channel':'Deferred','channel_version':'2208'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14931.20926','channel':'Deferred','channel_version':'2202'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.14326.21336','channel':'Deferred'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.16026.20200','channel':'2021 Retail'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.16026.20200','channel':'2019 Retail'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16026.20200','channel':'2016 Retail'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.14332.20461','channel':'LTSC 2021'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10395.20020','channel':'2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Office'
);

