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
  script_id(106189);
  script_version("1.5");
  script_cvs_date("Date: 2018/08/29 17:01:11");

  script_cve_id(
    "CVE-2018-0792",
    "CVE-2018-0793",
    "CVE-2018-0794",
    "CVE-2018-0819"
  );
  script_bugtraq_id(
    102373,
    102375,
    102381,
    102464
  );

  script_name(english:"Security Update for Microsoft Office (January 2018) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office 2016 application installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2018-0792)

  - A remote code execution vulnerability exists in the way that
    Microsoft Outlook parses specially crafted email messages. An
    attacker who successfully exploited the vulnerability could take
    control of an affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts
    with full user rights. (CVE-2018-0793)

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2018-0794)

  - A spoofing vulnerability exists when Microsoft Outlook for MAC
    does not properly handle the encoding and display of email
    addresses. This improper handling and display may cause antivirus
    or antispam scanning to not work as intended. (CVE-2018-0819)"
  );
  # https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?68489292");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0792
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?54f02eaf");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0793
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?2f269c7f");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0794
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?4cb535bd");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2016 for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports(
    "installed_sw/Microsoft Outlook",
    "installed_sw/Microsoft Word"
  );

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

apps = make_list(
  "Microsoft Outlook",
  "Microsoft Word"
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

    if (version =~ "^15\.")
    {
      app_label += " for Mac 2016";
      fix = '16.9.0';
      fix_disp = '16.9 (18011602)';
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
