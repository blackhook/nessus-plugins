#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65254);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2013-2475",
    "CVE-2013-2476",
    "CVE-2013-2477",
    "CVE-2013-2478",
    "CVE-2013-2479",
    "CVE-2013-2480",
    "CVE-2013-2481",
    "CVE-2013-2482",
    "CVE-2013-2483",
    "CVE-2013-2484",
    "CVE-2013-2485",
    "CVE-2013-2486",
    "CVE-2013-2487",
    "CVE-2013-2488"
  );
  script_bugtraq_id(
    58340,
    58349,
    58350,
    58351,
    58353,
    58354,
    58355,
    58356,
    58357,
    58358,
    58362,
    58363,
    58364,
    58365
  );

  script_name(english:"Wireshark 1.8.x < 1.8.6 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.6.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist in the CSN.1, CIMD, DTLS, Mount, MS-MMS,
    RTPS, RTPS2, and TCP dissectors that could allow them 
    to crash. (Bugs 8274, 8332, 8335, 8346, 8380, 8382)

  - Errors exist in the AMPQ, FCSP, HART/IP, MPLS Echo,
    and RELOAD dissectors that could lead to an infinite
    loop, resulting in a denial of service. (Bugs 8039, 
    8337, 8359, 8360, 8364)

  - The ACN dissector can attempt a divide by zero
    operation that could lead to an application crash.
    (Bug 8340)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-11.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-21.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-22.html");

  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

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
  { 'min_version' : '1.8.0', 'max_version' : '1.8.5', 'fixed_version' : '1.8.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
