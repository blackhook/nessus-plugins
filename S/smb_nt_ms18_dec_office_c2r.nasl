##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##
include("compat.inc");

if (description)
{
  script_id(162079);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2018-8597", "CVE-2018-8627");

  script_name(english:"Security Updates for Microsoft Office Products C2R (December 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in Microsoft Excel
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2018-8597)

  - An information disclosure vulnerability exists when Microsoft
    Excel software reads out of bound memory due to an uninitialized
    variable, which could disclose the contents of memory. An
    attacker who successfully exploited the vulnerability could view
    out of bound memory. (CVE-2018-8627)");
  # https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#december-11-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e481e1d8");
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
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS18-12';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  {'product' : 'Microsoft Office 2016', 'channel':'Deferred', 'channel_version':'1803', 'file':'graph.exe', 'fixed_version': '16.0.9126.2336'},
  {'product' : 'Microsoft Office 2016', 'channel':'Deferred', 'file':'graph.exe', 'fixed_version': '16.0.8431.2351'},
  {'product' : 'Microsoft Office 2016', 'channel':'First Release for Deferred',  'file':'graph.exe', 'fixed_version': '16.0.10730.20262'},
  {'product' : 'Microsoft Office 2016', 'channel':'Current', 'file':'graph.exe', 'fixed_version': '16.0.11029.20108'},
  {'product' : 'Microsoft Office 2019', 'channel':'2019 Retail', 'file':'graph.exe', 'fixed_version': '16.0.11029.20108'},
  {'product' : 'Microsoft Office 2019', 'channel':'2019 Volume', 'file':'graph.exe', 'fixed_version': '16.0.10339.20026'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Excel'
);

