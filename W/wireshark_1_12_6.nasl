#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84398);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2015-4651", "CVE-2015-4652");
  script_bugtraq_id(75316, 80230);

  script_name(english:"Wireshark 1.12.x < 1.12.6 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.6. It is, therefore, affected by multiple denial
of service vulnerabilities :

  - An unspecified flaw exists in the WCCP dissector. A
    remote attacker can exploit this flaw, by injecting a
    specially crafted packet or by convincing a user to open
    a malformed PCAP file, to crash the application.
    (CVE-2015-4651)

  - An unspecified flaw exists in the GSM DTAP dissector. A
    remote attacker can exploit this flaw, by injecting a
    specially crafted packet or by convincing a user to open
    a malformed PCAP file, to crash the application.
    (CVE-2015-4652)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.6.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.12.0', 'max_version' : '1.12.5', 'fixed_version' : '1.12.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
