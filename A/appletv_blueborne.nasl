#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103223);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-14315");

  script_name(english:"Apple TV <= 7.2.2 Bluetooth Remote Code Execution (BlueBorne)");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version equal
or prior to 7.2.2. It is, therefore, affected by a remote code execution
vulnerability. A flaw exists related to the BlueTooth subsystem that
could allow remote code execution in the context of the privileged Bluetooth
service. This issue is also known as 'BlueBorne'.");
  script_set_attribute(attribute:"see_also", value:"https://www.armis.com/blueborne/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a 4th Generation Apple TV device running tvOS 9.0 or higher.
There is currently no fix available for 1st, 2nd or 3rd generation Apple TV devices.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/URL", "AppleTV/Port");
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

fixed_build = "13T396";
tvos_ver = '9.0';
gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  affected_gen   : make_list(1, 2, 3, 4),
  model          : model,
  gen            : gen,
  fix_tvos_ver   : tvos_ver,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
