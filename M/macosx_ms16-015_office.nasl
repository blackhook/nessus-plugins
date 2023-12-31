#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(88880);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0054");
  script_bugtraq_id(82508, 82652, 82654);
  script_xref(name:"MSFT", value:"MS16-015");
  script_xref(name:"IAVA", value:"2016-A-0043-S");
  script_xref(name:"MSKB", value:"3134241");
  script_xref(name:"MSKB", value:"3137721");

  script_name(english:"MS16-015: Security Update for Microsoft Office to Address Remote Code Execution (3134226) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office installed on the remote Mac OS X host
is affected by multiple remote code execution vulnerabilities due to
improper handling of objects in memory. A remote attacker can exploit
these vulnerabilities by convincing a user to open a specially crafted
file in Microsoft Office, resulting in execution of arbitrary code in
the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-015");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011 and
Office 2016 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0054");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2016");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    path    = install['path'];
    app_label = app;
    if (version =~ "^14\.")
    {
      if (app !~ " for Mac 2011$") app_label += " for Mac 2011";
      fix = '14.6.1';
    }
    else
    {
      if (version =~ "^15\.") app_label += " for Mac 2016";
      fix = '15.19.1';
    }

    if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix;

      os = get_kb_item("Host/MacOSX/Version");

      if (os =~ "^Mac OS X 10\.[0-9](\.|$)" && app_label =~ " for Mac 2016$")
        report += '\n  Note              : Update will require Mac OS X 10.10.0 or later.\n';
      else report += '\n';
    }
  }
}

# Report findings.
if (!empty(report))
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
