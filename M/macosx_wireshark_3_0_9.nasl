#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134109);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_xref(name:"IAVB", value:"2020-B-0011-S");

  script_name(english:"Wireshark 3.0.x < 3.0.9 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 3.0.9. It is, therefore, affected by
multiple vulnerabilities as referenced in the wireshark-3.0.9 advisory.

  - The LTE RRC dissector could leak memory. It may be
    possible to make Wireshark consume excessive CPU
    resources by injecting a malformed packet onto the wire
    or by convincing someone to read a malformed packet
    trace file. (wireshark-bug-16341)

  - The WiMax DLMAP dissector could crash. It may be
    possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone
    to read a malformed packet trace file. (wireshark-
    bug-16368)

  - The EAP dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (wireshark-bug-16397)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.0.9.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16341");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-03");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16368");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-04");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16397");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.0.9 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Wireshark');

constraints = [
  { 'min_version' : '3.0.0', 'max_version' : '3.0.8', 'fixed_version' : '3.0.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
