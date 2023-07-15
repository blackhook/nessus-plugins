#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(132938);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-0650", "CVE-2020-0651");
  script_xref(name:"IAVA", value:"2020-A-0029-S");

  script_name(english:"Security Updates for Microsoft Office Products (January 2020) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac OS X host is missing a security update. It is,
therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists when Microsoft Excel
   improperly handles objects in memory. An attacker who successfully
   exploited the vulnerability could run arbitrary code in the context
   of the current user. To exploit the vulnerability, an attacker has to
   entice the logged on user to click a link or open a specially crafted
   file to gain control of the system with the priviledges of the logged
   on user. (CVE-2020-0650 CVE-2020-0651)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#january-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21a62786");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dae26676");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Word", "installed_sw/Microsoft Excel", "installed_sw/Microsoft PowerPoint", "installed_sw/Microsoft OneNote", "installed_sw/Microsoft Outlook");

  exit(0);
}
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');
include('vcf.inc');

os = get_kb_item_or_exit('Host/MacOSX/Version');
apps = make_list(
  'Microsoft Word',
  'Microsoft Excel',
  'Microsoft PowerPoint',
  'Microsoft Outlook'
);
report = '';

#2016
min_ver_16 = '16';
fix_ver_16 = '16.16.18';
fix_disp_16 = '16.16.18 (20011202)';

#2019
min_ver_19 = '16.17.0';
fix_ver_19 = '16.33';
fix_disp_19 = '16.33 (20011301)';

foreach app (apps)
{
  installs = get_installs(app_name:app);
  if (isnull(installs[1]))
    continue;

  foreach install (installs[1])
  {
    version = install['version'];

    if (ver_compare(ver:version, minver:min_ver_19, fix:fix_ver_19, strict:FALSE) < 0)
    {
      app_label = app + ' for Mac 2019';
      report +=
        '\n\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp_19;
    }
    else if (ver_compare(ver:version, minver:min_ver_16, fix:fix_ver_16, strict:FALSE) < 0)
    {
      app_label = app + ' for Mac 2016';
      report +=
        '\n\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp_16;
    }
  }
}
if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

if (os =~ "^Mac OS X 10\.[0-9](\.|$)")
  report += '\n  Note              : Update will require Mac OS X 10.10.0 or later.\n';

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);

