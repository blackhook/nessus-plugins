#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154142);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2021-40454", "CVE-2021-40474", "CVE-2021-40485");
  script_xref(name:"IAVA", value:"2021-A-0465");
  script_xref(name:"IAVA", value:"2021-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0468-S");

  script_name(english:"Security Updates for Microsoft Office (October 2021) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities, as follows:

  - An information disclosure vulnerability in rich text editing that can be exploited by a low privileged,
    local user. (CVE-2021-40454)

  - Remote code execution vulnerabilities in Excel that can be exploited by an unauthenticated user.
    (CVE-2021-40474, CVE-2021-40485)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#october-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c345f31");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40474");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/Microsoft Excel");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/MacOSX/Version');
var apps = make_list('Microsoft Excel');
var report = '';

#2019
var min_ver_19 = '16.17.0';
var fix_ver_19 = '16.54';
var fix_disp_19 = '16.54 (21101001)';

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
      var app_label = app + ' for Mac 2019';
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

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
