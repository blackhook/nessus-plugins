#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176372);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058");
  script_xref(name:"IAVB", value:"2018-B-0120-S");

  script_name(english:"Wireshark 2.2.x < 2.2.17 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 2.2.17. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-2.2.17 advisory.

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Bluetooth AVDTP dissector could
    crash. This was addressed in epan/dissectors/packet-btavdtp.c by properly initializing a data structure.
    (CVE-2018-16058)

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Bluetooth Attribute Protocol
    dissector could crash. This was addressed in epan/dissectors/packet-btatt.c by verifying that a dissector
    for a specific UUID exists. (CVE-2018-16056)

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Radiotap dissector could crash. This
    was addressed in epan/dissectors/packet-ieee80211-radiotap-iter.c by validating iterator operations.
    (CVE-2018-16057)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.17.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/14884");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-44");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/14994");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-45");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/15022");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-46");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/29");
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
  { 'min_version' : '2.2.0', 'max_version' : '2.2.16', 'fixed_version' : '2.2.17' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
