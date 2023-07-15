#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69881);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2013-4933",
    "CVE-2013-5717",
    "CVE-2013-5718",
    "CVE-2013-5719",
    "CVE-2013-5720",
    "CVE-2013-5721",
    "CVE-2013-5722"
  );
  script_bugtraq_id(61471, 62315, 62318, 62319, 62320, 62321, 62322, 62868);

  script_name(english:"Wireshark 1.10.x < 1.10.2 Multiple DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.10 is earlier than 1.10.2.  It is,
therefore, affected by denial of service vulnerabilities in the
following dissectors :

  - Bluetooth HCI ACL (Bug #8722)
  - NBAP (Bug #9005)
  - NBAP (Bug #9005)
  - ASSA R3 (Bug #9020)
  - RTPS (Bug #9019)
  - MQ (Bug #9079)
  - LDAP (No bug ID)
  - Netmon file parser (Bug #8742)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-54.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-56.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-57.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-58.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-59.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-60.html");

  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.2.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

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
  { 'min_version' : '1.10.0', 'max_version' : '1.10.1', 'fixed_version' : '1.10.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
