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
  script_id(109944);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-8147", "CVE-2018-8162", "CVE-2018-8176");
  script_bugtraq_id(104035, 104058, 104184);
  script_xref(name:"IAVA", value:"2018-A-0151-S");

  script_name(english:"Security Update for Microsoft Office (May 2018) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office 2016 application installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

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
    rights. (CVE-2018-8147)

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
    rights. (CVE-2018-8162)

  - A remote code execution vulnerability exists in Microsoft
    PowerPoint software when the software fails to properly validate
    XML content. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of the
    current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected
    system. An attacker could then install programs, view, change, or
    delete data; or create new accounts with full user rights. Users
    whose accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate with
    administrative user rights. (CVE-2018-8176)");
  # https://support.office.com/en-us/article/update-history-for-office-2016-for-mac-700cab62-0d67-4f23-947b-3686cb1a8eb7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71b0d8f4");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8147
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3e03b8b");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8162
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db61e8c0");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8176
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b02d805");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2016 for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Excel", "installed_sw/Microsoft PowerPoint");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

apps = make_list(
  "Microsoft Excel",
  "Microsoft PowerPoint"
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
      fix = '16.13.0';
      fix_disp = '16.13 (18051301)';
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
