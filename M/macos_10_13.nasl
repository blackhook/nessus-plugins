#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103598);
  script_version("1.9");
  script_cvs_date("Date: 2018/07/14  1:59:37");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-4736",
    "CVE-2016-5387",
    "CVE-2016-8740",
    "CVE-2016-8743",
    "CVE-2016-9042",
    "CVE-2016-9063",
    "CVE-2016-9840",
    "CVE-2016-9841",
    "CVE-2016-9842",
    "CVE-2016-9843",
    "CVE-2017-0381",
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-6451",
    "CVE-2017-6452",
    "CVE-2017-6455",
    "CVE-2017-6458",
    "CVE-2017-6459",
    "CVE-2017-6460",
    "CVE-2017-6462",
    "CVE-2017-6463",
    "CVE-2017-6464",
    "CVE-2017-7074",
    "CVE-2017-7077",
    "CVE-2017-7078",
    "CVE-2017-7080",
    "CVE-2017-7082",
    "CVE-2017-7083",
    "CVE-2017-7084",
    "CVE-2017-7086",
    "CVE-2017-7114",
    "CVE-2017-7119",
    "CVE-2017-7121",
    "CVE-2017-7122",
    "CVE-2017-7123",
    "CVE-2017-7124",
    "CVE-2017-7125",
    "CVE-2017-7126",
    "CVE-2017-7127",
    "CVE-2017-7128",
    "CVE-2017-7129",
    "CVE-2017-7130",
    "CVE-2017-7132",
    "CVE-2017-7138",
    "CVE-2017-7141",
    "CVE-2017-7143",
    "CVE-2017-7144",
    "CVE-2017-7149",
    "CVE-2017-7150",
    "CVE-2017-7659",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9233",
    "CVE-2017-9788",
    "CVE-2017-9789",
    "CVE-2017-10140",
    "CVE-2017-10989",
    "CVE-2017-11103",
    "CVE-2017-13782",
    "CVE-2017-13807",
    "CVE-2017-13808",
    "CVE-2017-13809",
    "CVE-2017-13810",
    "CVE-2017-13811",
    "CVE-2017-13812",
    "CVE-2017-13813",
    "CVE-2017-13814",
    "CVE-2017-13815",
    "CVE-2017-13816",
    "CVE-2017-13817",
    "CVE-2017-13818",
    "CVE-2017-13819",
    "CVE-2017-13820",
    "CVE-2017-13821",
    "CVE-2017-13822",
    "CVE-2017-13823",
    "CVE-2017-13824",
    "CVE-2017-13825",
    "CVE-2017-13827",
    "CVE-2017-13828",
    "CVE-2017-13829",
    "CVE-2017-13830",
    "CVE-2017-13831",
    "CVE-2017-13832",
    "CVE-2017-13833",
    "CVE-2017-13834",
    "CVE-2017-13836",
    "CVE-2017-13837",
    "CVE-2017-13838",
    "CVE-2017-13839",
    "CVE-2017-13840",
    "CVE-2017-13841",
    "CVE-2017-13842",
    "CVE-2017-13843",
    "CVE-2017-13846",
    "CVE-2017-13850",
    "CVE-2017-13851",
    "CVE-2017-13853",
    "CVE-2017-13854",
    "CVE-2017-13873",
    "CVE-2017-1000373"
  );
  script_bugtraq_id(
    91816,
    93055,
    94337,
    94650,
    95076,
    95077,
    95078,
    95131,
    95248,
    97045,
    97046,
    97049,
    97050,
    97051,
    97052,
    97058,
    97074,
    97076,
    97078,
    97201,
    99132,
    99134,
    99135,
    99137,
    99170,
    99177,
    99276,
    99502,
    99551,
    99568,
    99569,
    100987,
    100990,
    100991,
    100992,
    100993,
    100999,
    102100
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-09-25-1");

  script_name(english:"macOS < 10.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is prior to
10.10.5, 10.11.x prior to 10.11.6, 10.12.x prior to 10.12.6, or is
not macOS 10.13. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - apache
  - AppSandbox
  - AppleScript
  - Application Firewall
  - ATS
  - Audio
  - CFNetwork
  - CFNetwork Proxies
  - CFString
  - Captive Network Assistant
  - CoreAudio
  - CoreText
  - DesktopServices
  - Directory Utility
  - file
  - Fonts
  - fsck_msdos
  - HFS
  - Heimdal
  - HelpViewer
  - IOFireWireFamily
  - ImageIO
  - Installer
  - Kernel
  - kext tools
  - libarchive
  - libc
  - libexpat
  - Mail
  - Mail Drafts
  - ntp
  - Open Scripting Architecture
  - PCRE
  - Postfix
  - Quick Look
  - QuickTime
  - Remote Management
  - SQLite
  - Sandbox
  - Screen Lock
  - Security
  - Spotlight
  - WebKit
  - zlib

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208144");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208165");
  # https://lists.apple.com/archives/security-announce/2017/Sep/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cfca404");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

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
fixed_version = "10.13";

# Patches exist for 10.10.5, OS X Yosemite v10.11.6 and OS X El Capitan v10.12.6
# https://support.apple.com/en-us/HT208221
# Do NOT mark them as vuln
if (
  # No 10.x patch below 10.10.5
  ver_compare(ver:version, fix:'10.10.5', strict:FALSE) == -1
  ||
  # No 10.11.x patch below 10.11.6
  (
    version =~"^10\.11($|[^0-9])"
    &&
    ver_compare(ver:version, fix:'10.11.6', strict:FALSE) == -1
  )
  ||
  # No 10.12.x patch below 10.12.6
  (
    version =~"^10\.12($|[^0-9])"
    &&
    ver_compare(ver:version, fix:'10.12.6', strict:FALSE) == -1
  )
)
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
