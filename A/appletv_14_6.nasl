#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149992);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21779",
    "CVE-2021-30663",
    "CVE-2021-30665",
    "CVE-2021-30677",
    "CVE-2021-30682",
    "CVE-2021-30685",
    "CVE-2021-30686",
    "CVE-2021-30687",
    "CVE-2021-30689",
    "CVE-2021-30697",
    "CVE-2021-30700",
    "CVE-2021-30701",
    "CVE-2021-30704",
    "CVE-2021-30705",
    "CVE-2021-30707",
    "CVE-2021-30710",
    "CVE-2021-30715",
    "CVE-2021-30720",
    "CVE-2021-30724",
    "CVE-2021-30727",
    "CVE-2021-30734",
    "CVE-2021-30736",
    "CVE-2021-30737",
    "CVE-2021-30740",
    "CVE-2021-30744",
    "CVE-2021-30749"
  );
  script_xref(name:"APPLE-SA", value:"HT212532");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-05-20");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Apple TV < 14.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 14.6. It is therefore affected by
multiple vulnerabilities as described in the HT212532, including:

  - Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30665)

  - Processing a maliciously crafted audio file may lead to arbitrary code execution (CVE-2021-30707)

  - Processing maliciously crafted web content may lead to universal cross site scripting (CVE-2021-30689)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212532");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 14.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30740");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30749");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include('appletv_func.inc');

var url, port, build, model, fixed_build, gen, tvos_ver;

url = get_kb_item_or_exit('AppleTV/URL', msg:'Cannot determine Apple TV URL.');

port = get_kb_item_or_exit('AppleTV/Port', msg:'Cannot determine Apple TV port.');

build = get_kb_item_or_exit('AppleTV/Version', msg:'Cannot determine Apple TV version.');

model = get_kb_item_or_exit('AppleTV/Model', msg:'Cannot determine Apple TV model.');

fixed_build = '18L569';
tvos_ver = '14.6';

# determine gen from the model
gen = APPLETV_MODEL_GEN[model];

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
