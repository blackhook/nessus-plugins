#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103419);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-7080",
    "CVE-2017-7081",
    "CVE-2017-7083",
    "CVE-2017-7086",
    "CVE-2017-7087",
    "CVE-2017-7090",
    "CVE-2017-7091",
    "CVE-2017-7092",
    "CVE-2017-7093",
    "CVE-2017-7094",
    "CVE-2017-7095",
    "CVE-2017-7096",
    "CVE-2017-7098",
    "CVE-2017-7099",
    "CVE-2017-7100",
    "CVE-2017-7102",
    "CVE-2017-7103",
    "CVE-2017-7104",
    "CVE-2017-7105",
    "CVE-2017-7107",
    "CVE-2017-7108",
    "CVE-2017-7109",
    "CVE-2017-7110",
    "CVE-2017-7111",
    "CVE-2017-7112",
    "CVE-2017-7114",
    "CVE-2017-7115",
    "CVE-2017-7116",
    "CVE-2017-7117",
    "CVE-2017-7120",
    "CVE-2017-7127",
    "CVE-2017-7128",
    "CVE-2017-7129",
    "CVE-2017-7130",
    "CVE-2017-11120",
    "CVE-2017-11121"
  );
  script_bugtraq_id(
    100924,
    100927,
    100984,
    100985,
    100986,
    100987,
    100990,
    100992,
    100994,
    100995,
    100998,
    101005,
    101006
  );

  script_name(english:"Apple TV < 11 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 11. It is, therefore, affected by multiple vulnerabilities
as described in the HT208113 security advisory.

Note that only 4th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208113");
  # https://lists.apple.com/archives/security-announce/2017/Sep/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27cd33f6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 11 or later. Note that this update is only
available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11121");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_build = "15J381";
tvos_ver = '11';

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
