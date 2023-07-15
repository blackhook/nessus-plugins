#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169649);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2022-42842",
    "CVE-2022-42843",
    "CVE-2022-42845",
    "CVE-2022-42848",
    "CVE-2022-42849",
    "CVE-2022-42851",
    "CVE-2022-42852",
    "CVE-2022-42855",
    "CVE-2022-42856",
    "CVE-2022-42863",
    "CVE-2022-42864",
    "CVE-2022-42865",
    "CVE-2022-42866",
    "CVE-2022-42867",
    "CVE-2022-46689",
    "CVE-2022-46690",
    "CVE-2022-46691",
    "CVE-2022-46692",
    "CVE-2022-46693",
    "CVE-2022-46694",
    "CVE-2022-46695",
    "CVE-2022-46696",
    "CVE-2022-46698",
    "CVE-2022-46699",
    "CVE-2022-46700",
    "CVE-2022-46701"
  );
  script_xref(name:"APPLE-SA", value:"HT213535");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-12-13");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/04");

  script_name(english:"Apple TV < 16.2 Multiple Vulnerabilities (HT213535)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 16.2. It is therefore affected by
multiple vulnerabilities as described in the HT213535");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213535");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 16.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46700");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'macOS Dirty Cow Arbitrary File Write Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include('appletv_func.inc');

var url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
var port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

var build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

var model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

var fixed_build = '20K362';
var tvos_ver = '16.2';

# determine gen from the model
var gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  affected_gen   : make_list(4, 5, 6),
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
