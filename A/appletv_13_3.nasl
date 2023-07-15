#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132045);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/29");

  script_cve_id(
    "CVE-2019-8828",
    "CVE-2019-8830",
    "CVE-2019-8832",
    "CVE-2019-8833",
    "CVE-2019-8835",
    "CVE-2019-8836",
    "CVE-2019-8838",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2019-8848",
    "CVE-2019-15903"
  );
  script_xref(name:"APPLE-SA", value:"HT210790");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-12-06");

  script_name(english:"Apple TV < 13.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 13.3. It is therefore affected by
multiple vulnerabilities as described in the HT210790");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210790");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 13.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8838");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_build = "17K449";
tvos_ver = '13.3';

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
  severity       : SECURITY_HOLE
);
