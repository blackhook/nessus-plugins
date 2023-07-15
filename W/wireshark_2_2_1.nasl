#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93940);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");


  script_name(english:"Wireshark 2.2.x < 2.2.1 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
2.2.x prior to 2.2.1. It is, therefore, affected by multiple denial of
service vulnerabilities :

  - A denial of service vulnerability exists in the
    ncp2222_compile_dfilters() function within file
    epan/dissectors/packet-ncp2222.inc due to improper
    handling of NCP frames. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to crash the process.

  - A denial of service vulnerability exists in the
    dissect_disconnrequestresponse() function within file
    epan/dissectors/packet-btl2cap.c when handling short
    bluetooth service names. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to crash the process.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-56.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-57.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.2.0', 'max_version' : '2.2.0', 'fixed_version' : '2.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
