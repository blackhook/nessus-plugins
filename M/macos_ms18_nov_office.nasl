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
  script_id(118934);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8574", "CVE-2018-8577");
  script_bugtraq_id(105833, 105834);

  script_name(english:"Security Update for Microsoft Office (November 2018) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office for macOS");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS 
or Mac OS X host is missing a security update. It is, therefore, 
affected by the following vulnerability:

  - A remote code execution vulnerability exists in Microsoft Excel 
  software when the software fails to properly handle objects in
  memory. An attacker who successfully exploited the vulnerability
  could run arbitrary code in the context of the current user. If the
  current user is logged on with administrative user rights, an
  attacker could take control of the affected system. An attacker
  could then install programs; view, change, or delete data; or create
  new accounts with full user rights. Users whose accounts are
  configured to have fewer user rights on the system could be less
  impacted than users who operate with administrative user rights.

  Exploitation of the vulnerability requires that a user open a
  specially crafted file with an affected version of Microsoft Excel.
  In an email attack scenario, an attacker could exploit the
  vulnerability by sending the specially crafted file to the user and
  convincing the user to open the file. In a web-based attack
  scenario, an attacker could host a website (or leverage a
  compromised website that accepts or hosts user-provided content)
  containing a specially crafted file designed to exploit the
  vulnerability. An attacker would have no way to force users to visit
  the website. Instead, an attacker would have to convince users to
  click a link, typically by way of an enticement in an email or
  instant message, and then convince them to open the specially
  crafted file. The security update addresses the vulnerability by
  correcting how Microsoft Excel handles objects in memory
  (CVE-2018-8574, CVE-2018-8577)");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac#november-2018-release
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5696476b");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8574
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ca7f685");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8577
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5e3fcde");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Word", "installed_sw/Microsoft Excel", "installed_sw/Microsoft PowerPoint", "installed_sw/Microsoft OneNote", "installed_sw/Microsoft Outlook");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item_or_exit("Host/MacOSX/Version");

apps = make_list(
  "Microsoft Word",
  "Microsoft Excel",
  "Microsoft PowerPoint",
  "Microsoft OneNote",
  "Microsoft Outlook"
);

#2019
min_ver_19 = '16.17.0';
fix_ver_19 = '16.19.0';
fix_disp_19 = '16.19.0 (18110915)';

#2016
min_ver_16 = '16';
fix_ver_16 = '16.16.4';
fix_disp_16 = '16.16.4 (18111001)';
report = '';

for(i = 0; i < len(apps); i++)
{
  app = apps[i];
  installs = get_installs(app_name:app);
  if (isnull(installs[1])) continue;

  for(j = 0; j < len(installs[1]); j++)
  {
    install = installs[1][j];
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
  audit(AUDIT_HOST_NOT, "affected");


if (os =~ "^Mac OS X 10\.[0-9](\.|$)")
  report += '\n  Note              : Update will require Mac OS X 10.10.0 or later.\n';


security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
