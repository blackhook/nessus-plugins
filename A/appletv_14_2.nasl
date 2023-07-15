##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146215);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2020-9974",
    "CVE-2020-10002",
    "CVE-2020-10003",
    "CVE-2020-10010",
    "CVE-2020-10011",
    "CVE-2020-10016",
    "CVE-2020-10017",
    "CVE-2020-27899",
    "CVE-2020-27905",
    "CVE-2020-27909",
    "CVE-2020-27910",
    "CVE-2020-27911",
    "CVE-2020-27912",
    "CVE-2020-27916",
    "CVE-2020-27917",
    "CVE-2020-27918",
    "CVE-2020-27927",
    "CVE-2020-27935"
  );
  script_xref(name:"APPLE-SA", value:"HT211930");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-11-05-7");

  script_name(english:"Apple TV < 14.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 14.2. It is, therefore, affected by
multiple vulnerabilities as described in the HT211930 advisory:

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 14.2 and iPadOS
    14.2, tvOS 14.2, watchOS 7.1. A malicious application may be able to execute arbitrary code with system privileges.
    (CVE-2020-27905)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Big Sur 11.0.1,
    iOS 14.2 and iPadOS 14.2, tvOS 14.2, watchOS 7.1. Processing a maliciously crafted audio file may lead to arbitrary
    code execution. (CVE-2020-27910)

  - An integer overflow was addressed through improved input validation. This issue is fixed in macOS Big Sur 11.0.1,
    watchOS 7.1, iOS 14.2 and iPadOS 14.2, iCloud for Windows 11.5, tvOS 14.2, iTunes 12.11 for Windows. A remote
    attacker may be able to cause unexpected application termination or arbitrary code execution. (CVE-2020-27911)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 14.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27905");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include('appletv_func.inc');

url = get_kb_item_or_exit('AppleTV/URL', msg:'Cannot determine Apple TV URL.');

port = get_kb_item_or_exit('AppleTV/Port', msg:'Cannot determine Apple TV port.');

build = get_kb_item_or_exit('AppleTV/Version', msg:'Cannot determine Apple TV version.');

model = get_kb_item_or_exit('AppleTV/Model', msg:'Cannot determine Apple TV model.');

fixed_build = '18K57';
tvos_ver = '14.2';

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
