#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91311);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-1801",
    "CVE-2016-1802",
    "CVE-2016-1803",
    "CVE-2016-1807",
    "CVE-2016-1808",
    "CVE-2016-1811",
    "CVE-2016-1813",
    "CVE-2016-1814",
    "CVE-2016-1817",
    "CVE-2016-1818",
    "CVE-2016-1819",
    "CVE-2016-1823",
    "CVE-2016-1824",
    "CVE-2016-1827",
    "CVE-2016-1828",
    "CVE-2016-1829",
    "CVE-2016-1830",
    "CVE-2016-1832",
    "CVE-2016-1833",
    "CVE-2016-1834",
    "CVE-2016-1836",
    "CVE-2016-1837",
    "CVE-2016-1838",
    "CVE-2016-1839",
    "CVE-2016-1840",
    "CVE-2016-1841",
    "CVE-2016-1847",
    "CVE-2016-1854",
    "CVE-2016-1855",
    "CVE-2016-1856",
    "CVE-2016-1857",
    "CVE-2016-1858",
    "CVE-2016-1859",
    "CVE-2016-4650"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-05-16-1");

  script_name(english:"Apple TV < 9.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Apple TV device is
prior to 9.2.1. It is, therefore, affected by multiple vulnerabilities
in the following components :

  - CFNetwork Proxies
  - CommonCrypto
  - CoreCapture
  - Disk Images
  - ImageIO
  - IOAcceleratorFamily
  - IOHIDFamily
  - Kernel
  - libc
  - libxml2
  - libxslt
  - OpenGL
  - WebKit
  - WebKit Canvas

Note that only 4th generation models are affected by the
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206564");
  # https://lists.apple.com/archives/security-announce/2016/May/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?618f77f3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 9.2.1 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4650");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include("audit.inc");
include("appletv_func.inc");

url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

fixed_build = "13Y772";
tvos_ver = '9.2.1';

# determine gen from the model
gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  affected_gen   : 4,
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
