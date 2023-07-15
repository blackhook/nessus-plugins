#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81672);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2015-2187",
    "CVE-2015-2188",
    "CVE-2015-2189",
    "CVE-2015-2190",
    "CVE-2015-2191",
    "CVE-2015-2192"
  );
  script_bugtraq_id(
    72937,
    72938,
    72940,
    72941,
    72942
  );

  script_name(english:"Wireshark 1.10.x < 1.10.13 / 1.12.x < 1.12.4 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed remote Windows host is 1.10.x prior
to 1.10.13, or 1.12.x prior to 1.12.4. It is, therefore, affected by
denial of service vulnerabilities in the following items :

    - ATN-CPDLC dissector (CVE-2015-2187)
    - WCP dissector (CVE-2015-2188)
    - pcapng file parser (CVE-2015-2189)
    - LLDP dissector (CVE-2015-2190)
    - TNEF dissector (CVE-2015-2191)
    - SCSI OSD dissector (CVE-2015-2192)

A remote attacker can exploit these vulnerabilities to cause Wireshark
to crash or consume excessive CPU resources, either by injecting a
specially crafted packet onto the wire or by convincing a user to read
a malformed packet trace or PCAP file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-06.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-07.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-08.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-09.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-11.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2192");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.12.0', 'max_version' : '1.12.3', 'fixed_version' : '1.12.4' },
  { 'min_version' : '1.10.10', 'max_version' : '1.10.12', 'fixed_version' : '1.10.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
