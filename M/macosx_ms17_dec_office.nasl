#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(105177);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-11934");
  script_bugtraq_id(102064);
  script_xref(name:"IAVA", value:"2017-A-0363-S");

  script_name(english:"Security Update for Microsoft Office (December 2017) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office 2016 application installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by the following vulnerability:

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the user's
    computer or data. To exploit the vulnerability, an
    attacker could craft a special document file and then
    convince the user to open it. An attacker must know the
    memory address location where the object was created.
    The update addresses the vulnerability by changing the
    way certain functions handle objects in memory.
    (CVE-2017-11934)");
  # https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68489292");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-11934
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ec15154");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2016 for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft PowerPoint");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# 2017-Dec PowerPoint security updates only
apps = make_list(
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

    if (version =~ "^15\.")
    {
      app_label += " for Mac 2016";
      fix = '15.41.0';
      fix_disp = '15.41 (17120500)';
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
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
else
  audit(AUDIT_HOST_NOT, "affected");
