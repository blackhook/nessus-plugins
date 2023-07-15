#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176368);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/07");

  script_cve_id(
    "CVE-2023-0668",
    "CVE-2023-2855",
    "CVE-2023-2856",
    "CVE-2023-2857",
    "CVE-2023-2858",
    "CVE-2023-2879",
    "CVE-2023-2952"
  );
  script_xref(name:"IAVB", value:"2023-B-0036");

  script_name(english:"Wireshark 3.6.x < 3.6.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 3.6.14. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-3.6.14 advisory.

  - The Candump log file parser could crash. It may be possible to make Wireshark crash by convincing someone
    to read a malformed packet trace file. (CVE-2023-2855)

  - The BLF file parser could crash. It may be possible to make Wireshark crash by convincing someone to read
    a malformed packet trace file. (CVE-2023-2857)

  - The GDSDB dissector could go into an infinite loop. It may be possible to make Wireshark consume excessive
    CPU resources by injecting a malformed packet onto the wire or by convincing someone to read a malformed
    packet trace file. (wireshark-bug-19068)

  - The NetScaler file parser could crash. It may be possible to make Wireshark crash by convincing someone to
    read a malformed packet trace file. (CVE-2023-2858)

  - The VMS TCPIPtrace file parser could crash. It may be possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2023-2856)

  - The IEEE C37.118 Synchrophasor dissector could crash. It may be possible to make Wireshark crash by
    injecting a malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2023-0668)

  - The XRA dissector could go into an infinite loop. It may be possible to make Wireshark crash by injecting
    a malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (wireshark-bug-19100)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.6.14.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19062");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-12");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19063");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-13");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19068");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-14");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19081");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-15");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19083");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-16");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19087");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-19");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19100");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.6.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2952");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2879");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '3.6.0', 'max_version' : '3.6.13', 'fixed_version' : '3.6.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
