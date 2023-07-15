#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(177383);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-33140");
  script_xref(name:"IAVA", value:"2023-A-0303");

  script_name(english:"Microsoft OneNote Spoofing(June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft OneNote Products are affected by a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft OneNote Products are missing a security update. It is, therefore, affected by a spoofing
vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b315068b");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5931548c");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-33140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18e4c958");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 16.0.14326.21450  or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33140");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var apps = ['Microsoft.Office.OneNote'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

# added two check for 2 different version format
var constraints = [
    { 'min_version' : '16.0', 'fixed_version' : '16.14326.21450.0' },
    { 'min_version' : '16001.0', 'fixed_version' : '16001.14326.21450.0' }
];

# added path cheking to diffirentiate from other onenote
if (empty_or_null(app_info.path))
  vcf::audit(app_info);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);