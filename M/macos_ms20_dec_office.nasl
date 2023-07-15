##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(145269);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-17119",
    "CVE-2020-17123",
    "CVE-2020-17124",
    "CVE-2020-17126",
    "CVE-2020-17128"
  );
  script_xref(name:"IAVA", value:"2020-A-0556-S");
  script_xref(name:"IAVA", value:"2020-A-0559-S");
  script_xref(name:"IAVA", value:"2021-A-0017-S");
  script_xref(name:"IAVA", value:"2020-A-0558-S");
  script_xref(name:"IAVA", value:"2020-A-0557-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"Security Updates for Microsoft Office (December 2020) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office product installed on the remote host is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - Microsoft Excel Remote Code Execution Vulnerability (CVE-2020-17123, CVE-2020-17128)

  - Microsoft Excel Information Disclosure Vulnerability (CVE-2020-17126)

  - Microsoft Outlook Information Disclosure Vulnerability (CVE-2020-17119)

  - Microsoft PowerPoint Remote Code Execution Vulnerability (CVE-2020-17124)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#december-15-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97475468");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Excel", "installed_sw/Microsoft Word", "Microsoft PowerPoint");

  exit(0);
}

include('vcf.inc');

os = get_kb_item_or_exit('Host/MacOSX/Version');
apps = make_list(
  'Microsoft Excel',
  'Microsoft Outlook',
  'Microsoft PowerPoint'
);
report = '';

#2019
min_ver_19 = '16.17.0';
fix_ver_19 = '16.44';
fix_disp_19 = '16.44 (20121301)';

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
  }
}
if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

if (os =~ "^Mac OS X 10\.([0-9]([^0-9]|$)|1[0-3])")
  report += '\n  Note              : Update will require Mac OS X 10.14.0 or later.\n';

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
