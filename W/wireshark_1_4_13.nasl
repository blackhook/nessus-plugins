#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59239);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2012-2392",
    "CVE-2012-2393",
    "CVE-2012-2394",
    "CVE-2012-3825"
  );
  script_bugtraq_id(53651, 53652, 53653);
  script_xref(name:"EDB-ID", value:"18918");
  script_xref(name:"EDB-ID", value:"18919");
  script_xref(name:"EDB-ID", value:"18920");

  script_name(english:"Wireshark 1.4.x < 1.4.13 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.4.x before 1.4.13.  This
version is affected by the following vulnerabilities :

  - Input validation errors exist in the dissectors for
    ANSI MAP, ASF, BACapp, Bluetooth HCI, IEEE 802.11,
    IEEE 802.3, LTP, and R3 that can allow specially crafted
    packets to cause the application to enter infinite or
    very large loops making it unavailable. (Issues 6805,
    7118, 7119, 7120, 7121, 7122, 7124, 7125)

  - An input validation error exists in the DIAMETER
    dissector that can allow specially crafted packets to
    cause improper memory allocation leading to application
    crashes. (Issue 7138)

  - An unspecified error can cause the application to crash
    due to a memory misalignment. Note, for Windows, this
    issue only occurs on the Itanium platform. (Issue 7221)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-08.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-09.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-10.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.13.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.4.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3825");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.4.0', 'max_version' : '1.4.12', 'fixed_version' : '1.4.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
