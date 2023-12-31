#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57538);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2012-0041",
    "CVE-2012-0042",
    "CVE-2012-0043",
    "CVE-2012-0066",
    "CVE-2012-0067",
    "CVE-2012-0068"
  );
  script_bugtraq_id(51368, 51710);

  script_name(english:"Wireshark 1.4.x < 1.4.11 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.4.x before 1.4.11.  This
version is affected by the following vulnerabilities :

  - Errors exist in the parsers for '5views', 'i4b', 
    'iptrace', 'netmon2' and 'novell' packets that can lead
    to application crashes. (Issues #6663, 6666, 6667,
    6668, 6669, 6670)

  - An unspecified error exists in the display processing 
    of certain packets that can lead to a NULL pointer 
    dereference. (Issue #6634)

  - A buffer overflow exists in the 'RLC' dissector.
    (Issue #6391)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-03.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.11.html");
  script_set_attribute(attribute:"see_also", value:"https://downloads.securityfocus.com/vulnerabilities/exploits/51710.zip");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.4.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.4.0', 'max_version' : '1.4.10', 'fixed_version' : '1.4.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
