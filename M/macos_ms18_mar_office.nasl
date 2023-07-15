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
  script_id(108282);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0907", "CVE-2018-0919");
  script_xref(name:"IAVA", value:"2018-A-0077-S");

  script_name(english:"Security Update for Microsoft Office (March 2018) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office 2016 application installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

  - A security feature bypass vulnerability exists in Microsoft Office
    software by not enforcing macro settings on an Excel document. The
    security feature bypass by itself does not allow arbitrary code
    execution. To successfully exploit the vulnerability, an attacker
    would have to embed a control in an Excel worksheet that specifies
    a macro should be run. To exploit the vulnerability, an attacker
    would have to convince a user to open a specially crafted file
    with an affected version of Microsoft Office software. The
    security update addresses the vulnerability by enforcing macro
    settings on Excel documents. (CVE-2018-0907)

  - An information disclosure vulnerability exists when Microsoft
    Office software reads out of bound memory due to an uninitialized
    variable, which could disclose the contents of memory. An attacker
    who successfully exploited the vulnerability could view out of
    bound memory. (CVE-2018-0919(");
  # https://support.office.com/en-us/article/release-notes-for-office-2016-for-mac-ed2da564-6d53-4542-9954-7e3209681a41?ui=en-US&rs=en-US&ad=US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f07d9218");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0907
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6156de49");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0919
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d927b832");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2016 for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Office for Mac 2016 ", "installed_sw/Microsoft Excel");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

apps = make_list(
  "Office for Mac 2016",
  "Microsoft Excel"
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
      fix = '16.11.0';
      fix_disp = '16.11 (18031100)';
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
