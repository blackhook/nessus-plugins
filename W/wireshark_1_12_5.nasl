#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83488);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2015-3808",
    "CVE-2015-3809",
    "CVE-2015-3810",
    "CVE-2015-3811",
    "CVE-2015-3812",
    "CVE-2015-3813",
    "CVE-2015-3814",
    "CVE-2015-3815",
    "CVE-2015-3906"
  );
  script_bugtraq_id(
    74628,
    74629,
    74630,
    74631,
    74632,
    74633,
    74635,
    74637,
    74837
  );

  script_name(english:"Wireshark 1.10.x < 1.10.14 / 1.12.x < 1.12.5 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.10.x prior to 1.10.14, or 1.12.x prior to 1.12.5. It is, therefore,
affected by various denial of service vulnerabilities in the following
items :

  - LBMR dissector (CVE-2015-3808, CVE-2015-3809)

  - WebSocket dissector (CVE-2015-3810)

  - WCP dissector (CVE-2015-3811)

  - X11 dissector (CVE-2015-3812)

  - Packet reassembly code (CVE-2015-3813)

  - IEEE 802.11 dissector (CVE-2015-3814)

  - Android Logcat file parser (CVE-2015-3815,
    CVE-2015-3906)

A remote attacker can exploit these vulnerabilities to cause Wireshark
to crash or consume excessive CPU resources, either by injecting a
specially crafted packet onto the wire or by convincing a user to read
a malformed packet trace or PCAP file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.5.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.10.14 / 1.12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");

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
  { 'min_version' : '1.12.0', 'max_version' : '1.12.4', 'fixed_version' : '1.12.5' },
  { 'min_version' : '1.10.10', 'max_version' : '1.10.13', 'fixed_version' : '1.10.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
