#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164830);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");
  script_xref(name:"IAVB", value:"2022-B-0035-S");

  script_name(english:"Wireshark 3.6.x < 3.6.8 A Vulnerability (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 3.6.8. It is, therefore, affected by
a vulnerability as referenced in the wireshark-3.6.8 advisory.

  - The F5 Ethernet Trailer dissector could go into an infinite loop. It may be possible to make Wireshark
    consume excessive CPU resources by injecting a malformed packet onto the wire or by convincing someone to
    read a malformed packet trace file. (wireshark-bug-18307)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.6.8.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18307");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2022-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.6.8 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Wireshark');

var constraints = [
  { 'min_version' : '3.6.0', 'max_version' : '3.6.7', 'fixed_version' : '3.6.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
