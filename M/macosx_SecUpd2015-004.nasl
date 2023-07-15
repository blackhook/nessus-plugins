#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82700);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id(
    "CVE-2013-0118",
    "CVE-2013-5704",
    "CVE-2013-6438",
    "CVE-2013-6712",
    "CVE-2014-0098",
    "CVE-2014-0117",
    "CVE-2014-0118",
    "CVE-2014-0207",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-0237",
    "CVE-2014-0238",
    "CVE-2014-2497",
    "CVE-2014-3478",
    "CVE-2014-3479",
    "CVE-2014-3480",
    "CVE-2014-3487",
    "CVE-2014-3523",
    "CVE-2014-3538",
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-3587",
    "CVE-2014-3597",
    "CVE-2014-3668",
    "CVE-2014-3669",
    "CVE-2014-3670",
    "CVE-2014-3710",
    "CVE-2014-3981",
    "CVE-2014-4049",
    "CVE-2014-4380",
    "CVE-2014-4404",
    "CVE-2014-4405",
    "CVE-2014-4670",
    "CVE-2014-4698",
    "CVE-2014-5120",
    "CVE-2014-8275",
    "CVE-2014-8830",
    "CVE-2015-0204",
    "CVE-2015-1091",
    "CVE-2015-1093",
    "CVE-2015-1098",
    "CVE-2015-1099",
    "CVE-2015-1099",
    "CVE-2015-1100",
    "CVE-2015-1101",
    "CVE-2015-1104",
    "CVE-2015-1117",
    "CVE-2015-1131",
    "CVE-2015-1132",
    "CVE-2015-1133",
    "CVE-2015-1134",
    "CVE-2015-1135",
    "CVE-2015-1136",
    "CVE-2015-1137",
    "CVE-2015-1139",
    "CVE-2015-1140",
    "CVE-2015-1143",
    "CVE-2015-1144",
    "CVE-2015-1145",
    "CVE-2015-1146",
    "CVE-2015-1147",
    "CVE-2015-1545",
    "CVE-2015-1546"
  );
  script_bugtraq_id(
    58128,
    64018,
    66233,
    66303,
    66550,
    67759,
    67765,
    67837,
    68007,
    68120,
    68238,
    68239,
    68241,
    68243,
    68348,
    68511,
    68513,
    68678,
    68740,
    68742,
    68745,
    68747,
    69322,
    69325,
    69375,
    69938,
    69942,
    69947,
    70611,
    70665,
    70666,
    70807,
    71934,
    71935,
    71936,
    71937,
    71939,
    71942,
    72328,
    72519,
    73176,
    73984
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-04-08-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2015-004) (FREAK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.8.5 or 10.9.5
that is missing Security Update 2015-004. It is, therefore, affected
multiple vulnerabilities in the following components :

  - Apache
  - ATS
  - Certificate Trust Policy
  - CoreAnimation
  - FontParser
  - Graphics Driver
  - ImageIO
  - IOHIDFamily
  - Kernel
  - LaunchServices
  - Open Directory Client
  - OpenLDAP
  - OpenSSL
  - PHP
  - QuickLook
  - SceneKit
  - Security - Code SIgning
  - UniformTypeIdentifiers

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204659");
  # https://lists.apple.com/archives/security-announce/2015/Apr/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf90c4cb");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2015-004 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1132");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X IOKit Keyboard Driver Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

patch = "2015-004";

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:"-");
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Advisory states that the update is available for 10.10.2
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[89]\.5([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8.5 or Mac OS X 10.9.5");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = egrep(pattern:"^com\.apple\.pkg\.update\.security\..*bom$", string:packages);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  match = eregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(match[1]) || empty_or_null(match[2]))
    continue;

  patch_found = check_patch(year:int(match[1]), number:int(match[2]));
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
