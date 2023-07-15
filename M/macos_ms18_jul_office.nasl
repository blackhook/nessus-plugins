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
  script_id(110978);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8281");

  script_name(english:"Security Update for Microsoft Office (July 2018) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office 2016 application installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

  - A remote code execution vulnerability exists in Microsoft
    Office software when the software fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights. Users
    whose accounts are configured to have fewer user rights
    on the system could be less impacted than users who
    operate with administrative user rights. (CVE-2018-8281)");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17ce16bb");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8281
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdf86910");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2016 for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

apps = make_list(
  "Microsoft Word",
  "Microsoft Excel",
  "Microsoft PowerPoint",
  "Microsoft OneNote",
  "Microsoft Outlook"
);

report = "";

foreach app (apps)
{
  installs = get_installs(app_name:app);
  if (isnull(installs[1])) continue;
  foreach install (installs[1])
  {
    version = install['version'];
    app_label = app;
    fix = NULL;
    fix_disp = NULL;

    if (version =~ "^16\.")
    {
      app_label += " for Mac 2016";
      fix = '16.15.0';
      fix_disp = '16.15 (18070902)';
    }

    if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp;

      fix_disp = '';
      if (os =~ "^Mac OS X 10\.[0-9](\.|$)")
        report += '\n  Note              : Update will require Mac OS X 10.10.0 or later.\n';
      else report += '\n';
    }
  }
}

# Report findings.
if (!empty(report))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
else
  audit(AUDIT_HOST_NOT, "affected");
