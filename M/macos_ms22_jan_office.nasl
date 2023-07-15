##
# (C) Tenable, Inc. 
##

#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157385);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-21840", "CVE-2022-21841");
  script_xref(name:"IAVA", value:"2022-A-0018-S");

  script_name(english:"Security Updates for Microsoft Office Products (January 2022) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-21840,
    CVE-2022-21841)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#january-13-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?917d805e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21841");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Outlook", "installed_sw/Microsoft Excel", "installed_sw/Microsoft Word", "installed_sw/Microsoft PowerPoint", "installed_sw/Microsoft OneNote");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/MacOSX/Version');
var apps = make_list('Microsoft Outlook', 'Microsoft Excel', 'Microsoft Excel', 'Microsoft Word', 
                     'Microsoft PowerPoint','Microsoft OneNote');
var report = '';

# 2019/2021
var min_ver_19 = '16.17.0';
var fix_ver_19 = '16.57';
var fix_disp_19 = '16.57 (22011101)';

foreach var app (apps)
{
  var installs = get_installs(app_name:app);
  if (isnull(installs[1]))
    continue;

  foreach var install (installs[1])
  {
    var version = install['version'];

    if (ver_compare(ver:version, minver:min_ver_19, fix:fix_ver_19, strict:FALSE) < 0)
    {
      var app_label = app + ' for Mac';
      report +=
        '\n\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp_19;
    }
  }
}
if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

if (os =~ "^Mac OS X 10\.([0-9]([^0-9]|$)|1[0-4])")
  report += '\n  Note              : Update will require macOS 10.15.0 or later.\n';

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
