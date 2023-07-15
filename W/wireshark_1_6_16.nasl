#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(66894);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");

  script_cve_id("CVE-2013-4074", "CVE-2013-4081", "CVE-2013-4083");
  script_bugtraq_id(
    60448,
    60500,
    60504,
    60505
  );

  script_name(english:"Wireshark 1.6.x < 1.6.16 Multiple DoS Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.6 is earlier than 1.6.16.  It is,
therefore, affected by multiple denial of service vulnerabilities:

  - Errors exist in the CAPWAP and DCP ETSI dissectors that 
    could allow them to crash. (Bugs 8717, 8725)

  - Errors exist in the HTTP dissector that could overrun
    the stack, which could result in an application crash.
    (Bug 8733)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8725");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-32");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8733");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-39");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8717");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.6.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4083");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");

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
  { 'min_version' : '1.6.0', 'max_version' : '1.6.15', 'fixed_version' : '1.6.16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
