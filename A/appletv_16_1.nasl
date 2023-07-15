#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166680);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id(
    "CVE-2022-32923",
    "CVE-2022-32924",
    "CVE-2022-32926",
    "CVE-2022-32940",
    "CVE-2022-32944",
    "CVE-2022-42798",
    "CVE-2022-42799",
    "CVE-2022-42801",
    "CVE-2022-42803",
    "CVE-2022-42808",
    "CVE-2022-42810",
    "CVE-2022-42811",
    "CVE-2022-42813",
    "CVE-2022-42823",
    "CVE-2022-42824",
    "CVE-2022-42825"
  );
  script_xref(name:"APPLE-SA", value:"HT213492");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-10-27");

  script_name(english:"Apple TV < 16.1 Multiple Vulnerabilities (HT213492)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 16.1. It is therefore affected by
multiple vulnerabilities as described in the HT213492:

  - Processing maliciously crafted web content may disclose internal states of the app (CVE-2022-32923)
  
  - An app may be able to execute arbitrary code with kernel privileges (CVE-2022-32924)
  
  - An app with root privileges may be able to execute arbitrary code with kernel privileges (CVE-2022-32926)
  
  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
  number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213492");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 16.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42823");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var fixed_build = '20K71';
var tvos_ver = '16.1';

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
