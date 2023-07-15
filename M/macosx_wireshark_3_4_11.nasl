#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156389);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2021-4181",
    "CVE-2021-4182",
    "CVE-2021-4184",
    "CVE-2021-4185",
    "CVE-2021-4186"
  );
  script_xref(name:"IAVB", value:"2021-B-0072-S");
  script_xref(name:"IAVB", value:"2022-B-0035-S");

  script_name(english:"Wireshark 3.4.x < 3.4.11 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 3.4.11. It is, therefore, affected by
multiple vulnerabilities as referenced in the wireshark-3.4.11 advisory.

  - The Gryphon dissector could crash. It may be possible to make Wireshark crash by injecting a malformed
    packet onto the wire or by convincing someone to read a malformed packet trace file. (CVE-2021-4186)

  - The RTMPT dissector could go into an infinite loop. It may be possible to make Wireshark consume excessive
    CPU resources by injecting a malformed packet onto the wire or by convincing someone to read a malformed
    packet trace file. (CVE-2021-4185)

  - The BitTorrent DHT dissector could go into an infinite loop. It may be possible to make Wireshark crash by
    injecting a malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2021-4184)

  - The RFC 7468 file parser could go into an infinite loop. It may be possible to make Wireshark consume
    excessive CPU resources by convincing someone to read a malformed packet trace file. (CVE-2021-4182)

  - The Sysdig Event dissector could crash. It may be possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2021-4181)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.4.11.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-16");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-17");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-18");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-20");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-21");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.4.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Wireshark');

var constraints = [
  { 'min_version' : '3.4.0', 'max_version' : '3.4.10', 'fixed_version' : '3.4.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
