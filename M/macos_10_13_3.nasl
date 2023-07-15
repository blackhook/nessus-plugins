#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106296);
  script_version("1.10");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-13889",
    "CVE-2017-5705",
    "CVE-2017-5708",
    "CVE-2017-7830",
    "CVE-2017-8816",
    "CVE-2017-8817",
    "CVE-2018-4082",
    "CVE-2018-4083",
    "CVE-2018-4084",
    "CVE-2018-4085",
    "CVE-2018-4086",
    "CVE-2018-4088",
    "CVE-2018-4089",
    "CVE-2018-4090",
    "CVE-2018-4091",
    "CVE-2018-4092",
    "CVE-2018-4093",
    "CVE-2018-4094",
    "CVE-2018-4096",
    "CVE-2018-4097",
    "CVE-2018-4098",
    "CVE-2018-4100",
    "CVE-2018-4147",
    "CVE-2018-4169",
    "CVE-2018-4189"
  );
  script_bugtraq_id(
    101832,
    101917,
    101921,
    101998,
    102057,
    102772,
    102775,
    102778,
    102782,
    102785,
    103330
  );
  script_name(english:"macOS 10.13.x < 10.13.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.13.x
prior to 10.13.3. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Audio
  - curl
  - IOHIDFamily
  - Kernel
  - LinkPresentation
  - QuartzCore
  - Sandbox
  - Security
  - WebKit
  - Wi-Fi

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208465");
  # https://lists.apple.com/archives/security-announce/2018/Jan/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19644313");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.13.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4189");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

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
fixed_version = "10.13.3";

if (version !~"^10\.13($|[^0-9])")
  audit(AUDIT_OS_NOT, "macOS 10.13.x");

if (ver_compare(ver:version, fix:'10.13.3', strict:FALSE) == -1)
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
