#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(166060);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-38048", "CVE-2022-38049", "CVE-2022-41031");
  script_xref(name:"IAVA", value:"2022-A-0412-S");

  script_name(english:"Security Updates for Microsoft Word Products C2R (October 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update. It is, therefore, affected by multiple remote code execution
vulnerabilities. Unauthenticated attackers can exploit these to execute code on the affected system.");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#october-11-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1217239b");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-10';

var constraints = [
  {'fixed_version':'16.0.15629.20208','channel':'2016 Retail'},
  {'fixed_version':'16.0.15629.20208','channel':'Current'},
  {'fixed_version':'16.0.15601.20230','channel':'Enterprise Deferred','channel_version':'2208'},
  {'fixed_version':'16.0.15427.20308','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.15601.20230','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.14931.20764','channel':'Deferred','channel_version':'2202'},
  {'fixed_version':'16.0.14326.21186','channel':'Deferred'},
  {'fixed_version':'16.0.12527.22239','channel':'Microsoft 365 Apps on Windows 7'},
  {'fixed_version':'16.0.15629.20208','channel':'2021 Retail'},
  {'fixed_version':'16.0.15629.20208','channel':'2019 Retail'},
  {'fixed_version':'16.0.14332.20400','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10391.20029','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Word'
);

