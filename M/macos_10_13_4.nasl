#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108786);
  script_version("1.6");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-13080",
    "CVE-2017-13890",
    "CVE-2017-13911",
    "CVE-2017-15412",
    "CVE-2017-7151",
    "CVE-2018-4104",
    "CVE-2018-4105",
    "CVE-2018-4106",
    "CVE-2018-4107",
    "CVE-2018-4108",
    "CVE-2018-4111",
    "CVE-2018-4112",
    "CVE-2018-4115",
    "CVE-2018-4131",
    "CVE-2018-4132",
    "CVE-2018-4135",
    "CVE-2018-4136",
    "CVE-2018-4138",
    "CVE-2018-4139",
    "CVE-2018-4142",
    "CVE-2018-4143",
    "CVE-2018-4144",
    "CVE-2018-4150",
    "CVE-2018-4151",
    "CVE-2018-4152",
    "CVE-2018-4154",
    "CVE-2018-4155",
    "CVE-2018-4156",
    "CVE-2018-4157",
    "CVE-2018-4158",
    "CVE-2018-4160",
    "CVE-2018-4167",
    "CVE-2018-4170",
    "CVE-2018-4173",
    "CVE-2018-4174",
    "CVE-2018-4175",
    "CVE-2018-4176",
    "CVE-2018-4179",
    "CVE-2018-4185",
    "CVE-2018-4187",
    "CVE-2018-4298"
  );
  script_bugtraq_id(
    101274,
    102098,
    103579,
    103581,
    103582,
    103958,
    104223
  );
  script_name(english:"macOS 10.13.x < 10.13.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is
10.13.x prior to 10.13.4. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Admin Framework
  - APFS
  - ATS
  - CoreFoundation
  - CoreText
  - Disk Images
  - Disk Management
  - File System Events
  - iCloud Drive
  - Intel Graphics Driver
  - IOFireWireFamily
  - Kernel
  - kext tools
  - LaunchServices
  - Mail
  - Notes
  - NSURLSession
  - NVIDIA Graphics Drivers
  - PDFKit
  - PluginKit
  - Quick Look
  - Security
  - Storage
  - System Preferences
  - Terminal
  - WindowServer

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208692");
  # https://lists.apple.com/archives/security-announce/2018/Mar/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0e00f71");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.13.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4298");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (empty_or_null(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
fixed_version = "10.13.4";

if (version !~"^10\.13($|[^0-9])")
  audit(AUDIT_OS_NOT, "macOS 10.13.x");

if (ver_compare(ver:version, fix:'10.13.4', strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
