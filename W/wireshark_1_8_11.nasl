#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70763);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2013-6336",
    "CVE-2013-6337",
    "CVE-2013-6338",
    "CVE-2013-6339",
    "CVE-2013-6340"
  );
  script_bugtraq_id(63500, 63501, 63502, 63503, 63504);

  script_name(english:"Wireshark 1.8.x < 1.8.11 Multiple DoS Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8.x is earlier than 1.8.11.  It
is, therefore, affected by denial of service vulnerabilities in the
following dissectors :

  - IEEE 802.15.4 (Bug #9139)
  - NBAP (Bug #9168)
  - SIP (Bug #9228)
  - ActiveMQ OpenWire (Bug #9248)
  - TCP (Bug #9263)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-61.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-62.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-63.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-64.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-65.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.11.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.8.0', 'max_version' : '1.8.10', 'fixed_version' : '1.8.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
