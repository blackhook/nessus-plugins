#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161757);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-40442", "CVE-2021-42292");
  script_xref(name:"IAVA", value:"2021-A-0541");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/01");

  script_name(english:"Security Updates for Microsoft Excel Products C2R (November 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2021-42292)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-40442)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ab6861");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42292");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-11';

var constraints = [
  { 'channel':'Deferred', 'channel_version':'2102',  'fixed_version': '16.0.13801.21050'},
  { 'channel':'Deferred', 'fixed_version': '16.0.13127.21820'},
  { 'channel':'Microsoft 365 Apps on Windows 7',  'fixed_version': '16.0.12527.22060'},
  { 'channel':'Enterprise Deferred', 'channel_version':'2109',  'fixed_version': '16.0.14430.20342'},
  { 'channel':'Enterprise Deferred',  'fixed_version': '16.0.14326.20600'},
  { 'channel':'First Release for Deferred',  'fixed_version': '16.0.14326.20600'},
  { 'channel':'2016 Retail',  'fixed_version': '16.0.14527.20276'},
  { 'channel':'Current',  'fixed_version': '16.0.14527.20276'},
  { 'channel':'2019 Volume',  'fixed_version': '16.0.10380.20037'},
  { 'channel':'2019 Retail',  'fixed_version': '16.0.14527.20276'},
  { 'channel':'LTSC 2021',  'fixed_version': '16.0.14332.20176'},
  { 'channel':'2021 Retail',  'fixed_version': '16.0.14527.20276'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Excel'
);

