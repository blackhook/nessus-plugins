#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111110);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-4248",
    "CVE-2018-4261",
    "CVE-2018-4262",
    "CVE-2018-4263",
    "CVE-2018-4264",
    "CVE-2018-4265",
    "CVE-2018-4266",
    "CVE-2018-4267",
    "CVE-2018-4270",
    "CVE-2018-4271",
    "CVE-2018-4272",
    "CVE-2018-4273",
    "CVE-2018-4277",
    "CVE-2018-4278",
    "CVE-2018-4280",
    "CVE-2018-4282",
    "CVE-2018-4284",
    "CVE-2018-4293"
  );
  script_bugtraq_id(
    103957,
    103958,
    103961,
    104378
  );

  script_name(english:"Apple TV < 11.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 11.4.1. It is, therefore, affected by multiple
vulnerabilities as described in the HT208936 security advisory.

Note that only 4th and 5th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208936");
  # https://lists.apple.com/archives/security-announce/2018/Jul/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf6d645c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 11.4.1 or later. Note that this update is
only available for 4th and 5th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");

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
fixed_build = "15M73";
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
