#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63095);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2012-6053",
    "CVE-2012-6058",
    "CVE-2012-6059",
    "CVE-2012-6060",
    "CVE-2012-6061",
    "CVE-2012-6062"
  );
  script_bugtraq_id(56729);

  script_name(english:"Wireshark 1.6.x < 1.6.12 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.6 is earlier than 1.6.12.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist related to the USB, ICMPv6, iSCSI, WTP,
    and RTCP dissectors that could allow denial of service
    attacks by putting the application into an infinite 
    loop. (Bug 7787, 7844, 7858, 7869, 7879)

  - An error exists in the ISAKMP dissector that could allow
    a malformed packet to crash the application. (Bug 7855)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-31.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-35.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-36.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-37.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-38.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-40.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.6.12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.6.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/29");

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
  { 'min_version' : '1.6.0', 'max_version' : '1.6.11', 'fixed_version' : '1.6.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
