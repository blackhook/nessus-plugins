#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155571);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-39921",
    "CVE-2021-39922",
    "CVE-2021-39923",
    "CVE-2021-39924",
    "CVE-2021-39925",
    "CVE-2021-39928",
    "CVE-2021-39929"
  );
  script_xref(name:"IAVB", value:"2021-B-0065-S");

  script_name(english:"Wireshark 3.2.x < 3.2.18 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 3.2.18. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-3.2.18 advisory.

  - The Bluetooth DHT dissector could crash. It may be possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2021-39929)

  - The Bluetooth SDP dissector could crash. It may be possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2021-39925)

  - The Bluetooth DHT dissector could go into a large loop It may be possible to make Wireshark consume
    excessive CPU resources by injecting a malformed packet onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2021-39924)

  - The C12.22 dissector could crash. It may be possible to make Wireshark crash by injecting a malformed
    packet onto the wire or by convincing someone to read a malformed packet trace file. (CVE-2021-39922)

  - The IEEE 802.11 dissector could crash. It may be possible to make Wireshark crash by injecting a malformed
    packet onto the wire or by convincing someone to read a malformed packet trace file. (CVE-2021-39928)

  - The Modbuss dissector could crash. It may be possible to make Wireshark crash by injecting a malformed
    packet onto the wire or by convincing someone to read a malformed packet trace file. (CVE-2021-39921)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.2.18.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17651");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-07");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17635");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-09");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17677");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-10");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17684");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-11");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17636");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-12");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17704");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-13");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/17703");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2021-14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.2.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '3.2.0', 'max_version' : '3.2.17', 'fixed_version' : '3.2.18' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
