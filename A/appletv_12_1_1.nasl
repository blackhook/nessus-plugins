#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119839);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2018-4303",
    "CVE-2018-4431",
    "CVE-2018-4435",
    "CVE-2018-4436",
    "CVE-2018-4437",
    "CVE-2018-4438",
    "CVE-2018-4441",
    "CVE-2018-4442",
    "CVE-2018-4443",
    "CVE-2018-4447",
    "CVE-2018-4460",
    "CVE-2018-4461",
    "CVE-2018-4464",
    "CVE-2018-4465"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-12-05-3");

  script_name(english:"Apple TV < 12.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 12.1.1. It is, therefore, affected by multiple
vulnerabilities as described in the HT209342 security advisory:

  - Multiple elevation of privilege vulnerabilities exist due to
    improper memory handling. An application can exploit this to gain
    elevated privileges. (CVE-2018-4303, CVE-2018-4435)

  - Multiple unspecified command execution vulnerabilities exist that
    allow an attacker to execute arbitrary commands, sometimes with
    kernel privileges. (CVE-2018-4427, CVE-2018-4437, CVE-2018-4438,
    CVE-2018-4447, CVE-2018-4461, CVE-2018-4464, CVE-2018-4441,
    CVE-2018-4442, CVE-2018-4443)

  - An unspecified denial of service (DoS) vulnerability exists in
    the Kernel that allows an an attacker in a privileged position to
    perform a denial of service attack. (CVE-2018-4460)

Additionally, the version of Apple TV is also affected by several
additional vulnerabilities including cross-site scripting (XSS) and
an information disclosure vulnerability.

Note that only 4th generation devices are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209342");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 12.1.1 or later. Note that this update is
only available for 4th and 5th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4465");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-4464");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# https://en.wikipedia.org/wiki/TvOS
# 4th gen model "5,3" and 5th gen model "6,2" share same build
fixed_build = "16K45";
tvos_ver = '12.1.1';

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
