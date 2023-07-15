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
  script_id(103126);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8567",
    "CVE-2017-8631",
    "CVE-2017-8632",
    "CVE-2017-8676"
  );
  script_bugtraq_id(
    100719,
    100734,
    100751,
    100755
  );
  script_xref(name:"MSKB", value:"3212225");
  script_xref(name:"MSFT", value:"MS17-3212225");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Update for Microsoft Office (September 2017) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac
OS X host is missing a security update. It is, therefore, affected by
the following vulnerabilities:

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    Exploitation of the vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft Office software. In an email attack
    scenario, an attacker could exploit the vulnerability by
    sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based
    attack scenario, an attacker could host a website (or
    leverage a compromised website that accepts or hosts
    user-provided content) that contains a specially crafted
    file designed to exploit the vulnerability. An attacker
    would have no way to force users to visit the website.
    Instead, an attacker would have to convince users to
    click a link, typically by way of an enticement in an
    email or instant message, and then convince them to open
    the specially crafted file. Note that the Preview Pane
    is not an attack vector for this vulnerability. The
    security update addresses the vulnerability by
    correcting how Office handles objects in memory.
    (CVE-2017-8567)

  - A remote code execution vulnerability exists in
    Microsoft Office software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. Exploitation of
    this vulnerability requires that a user open a specially
    crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) that contains a specially crafted file that is
    designed to exploit the vulnerability. However, an
    attacker would have no way to force the user to visit
    the website. Instead, an attacker would have to convince
    the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and
    then convince the user to open the specially crafted
    file. The security update addresses the vulnerability by
    correcting how Microsoft Office handles files in memory.
    (CVE-2017-8631, CVE-2017-8632)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. To exploit this vulnerability, an
    attacker would have to log on to an affected system and
    run a specially crafted application. Note that where the
    severity is indicated as Critical in the Affected
    Products table, the Preview Pane is an attack vector for
    this vulnerability. The security update addresses the
    vulnerability by correcting how GDI handles memory
    addresses. (CVE-2017-8676)");
  # https://support.microsoft.com/en-us/help/3212225/description-of-the-security-update-for-office-for-mac-2011-14-7-7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6eeb83f");
  # https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68489292");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8631
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b333387a");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8632
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52db4138");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8676
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9e41e2a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set patches for Microsoft Office for Mac 2011
and Microsoft Office 2016 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Office for Mac 2011", "installed_sw/Microsoft Outlook", "installed_sw/Microsoft Excel", "installed_sw/Microsoft Word", "installed_sw/Microsoft PowerPoint", "installed_sw/Microsoft OneNote");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# Office 2011
apps = make_list(
  "Office for Mac 2011",
  "Microsoft Outlook",
  "Microsoft Excel",
  "Microsoft Word",
  "Microsoft PowerPoint",
  "Microsoft OneNote"
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

    if (version =~ "^14\.")
    {
      if (app !~ " for Mac 2011$") app_label += " for Mac 2011";
      fix = '14.7.7';
    }
    else
    {
      if (version =~ "^15\.") app_label += " for Mac 2016";
      fix = '15.38.0';
      fix_disp = '15.38 (17090200)';
    }

    if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Product           : ' + app_label +
        '\n  Installed version : ' + version;

      if (!empty_or_null(fix_disp))
      {
        report += '\n  Fixed version     : ' + fix_disp;
        fix_disp = '';
      }
      else report += '\n  Fixed version     : ' + fix;

      if (os =~ "^Mac OS X 10\.[0-9](\.|$)" && app_label =~ " for Mac 2016$")
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
