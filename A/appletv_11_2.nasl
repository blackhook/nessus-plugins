#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105612);
  script_version("1.9");
  script_cvs_date("Date: 2019/06/04  9:45:00");

  script_cve_id(
    "CVE-2017-7154",
    "CVE-2017-7156",
    "CVE-2017-7157",
    "CVE-2017-7160",
    "CVE-2017-7162",
    "CVE-2017-13833",
    "CVE-2017-13855",
    "CVE-2017-13856",
    "CVE-2017-13861",
    "CVE-2017-13862",
    "CVE-2017-13865",
    "CVE-2017-13866",
    "CVE-2017-13867",
    "CVE-2017-13868",
    "CVE-2017-13869",
    "CVE-2017-13870",
    "CVE-2017-13876"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-12-6-4");

  script_name(english:"Apple TV < 11.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 11.2. It is, therefore, affected by multiple
vulnerabilities as described in the HT208327 security advisory.

Note that only 4th and 5th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208327");
  # https://seclists.org/fulldisclosure/2017/Dec/29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?262ee1b8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 11.2 or later. Note that this update is
only available for 4th and 5th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7162");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Webkit Proxy Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
fixed_build = "15K106";
tvos_ver = '11';

# determine gen from the model
gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  affected_gen   : make_list(4, 5),
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_WARNING
);
