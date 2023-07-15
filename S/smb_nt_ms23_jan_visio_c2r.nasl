#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(169890);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2023-21736",
    "CVE-2023-21737",
    "CVE-2023-21738",
    "CVE-2023-21741"
  );
  script_xref(name:"IAVA", value:"2023-A-0030");

  script_name(english:"Security Updates for Microsoft Visio Products C2R (January 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visio Products are missing a security update. It is, therefore, affected by multiple vulnerabilities,
including the following:

  - Multiple remote code execution vulnerabilities. (CVE-2023-21736, CVE-2023-21737, CVE-2023-21738)

  - An information disclosure vulnerability. (CVE-2023-21741)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b315068b");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5931548c");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21741");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_visio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-01';

var constraints = [
  {'fixed_version':'16.0.15928.20216','channel':'Current'},
  {'fixed_version':'16.0.15831.20252','channel':'Enterprise Deferred','channel_version':'2211'},
  {'fixed_version':'16.0.15726.20292','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.15601.20456','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.15601.20456','channel':'Deferred','channel_version':'2208'},
  {'fixed_version':'16.0.14931.20888','channel':'Deferred','channel_version':'2202'},
  {'fixed_version':'16.0.14326.21286','channel':'Deferred'},
  {'fixed_version':'16.0.12527.22286','channel':'Microsoft 365 Apps on Windows 7'},
  {'fixed_version':'16.0.15928.20216','channel':'2021 Retail'},
  {'fixed_version':'16.0.15928.20216','channel':'2019 Retail'},
  {'fixed_version':'16.0.15928.20216','channel':'2016 Retail'},
  {'fixed_version':'16.0.14332.20447','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10394.20022','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Visio'
);

