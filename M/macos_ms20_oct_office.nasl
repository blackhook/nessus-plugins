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
  script_id(141470);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16918", "CVE-2020-16929", "CVE-2020-16933");
  script_xref(name:"IAVA", value:"2020-A-0454-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft Office (October 2020) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office product installed on the remote host is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability exists when the Base3D rendering engine handles memory. An attacker
    who successfully exploited the vulnerability would gain execution on a victim system. (CVE-2020-16918)

  - A remote code execution vulnerability exists in Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. (CVE-2020-16929)

  - A security feature bypass vulnerability exists in Microsoft Word software when it fails to properly handle
    .LNK files. An attacker who successfully exploited the vulnerability could use a specially crafted file to
    perform actions in the security context of the current user. (CVE-2020-16933)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16918");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-16933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Office for Mac 2011", "installed_sw/Microsoft Outlook", "installed_sw/Microsoft Excel", "installed_sw/Microsoft Word", "installed_sw/Microsoft PowerPoint", "installed_sw/Microsoft OneNote", "installed_sw/Microsoft Lync");

  exit(0);
}

include('vcf.inc');

os = get_kb_item_or_exit('Host/MacOSX/Version');
apps = make_list(
  'Microsoft Word',
  'Microsoft Excel',
  'Microsoft PowerPoint',
  'Microsoft OneNote',
  'Microsoft Outlook'
);
report = '';

#2016
min_ver_16 = '16';
fix_ver_16 = '16.16.27';
fix_disp_16 = '16.16.27 (20101200)';

#2019
min_ver_19 = '16.17.0';
fix_ver_19 = '16.42';
fix_disp_19 = '16.42 (20101102)';

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
