#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65253);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2012-6054",
    "CVE-2012-6056",
    "CVE-2013-2478",
    "CVE-2013-2480",
    "CVE-2013-2481",
    "CVE-2013-2482",
    "CVE-2013-2483",
    "CVE-2013-2484",
    "CVE-2013-2485",
    "CVE-2013-2488"
  );
  script_bugtraq_id(
    56729,
    58340,
    58351,
    58353,
    58355,
    58356,
    58357,
    58362,
    58365
  );

  script_name(english:"Wireshark 1.6.x < 1.6.14 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.6 is earlier than 1.6.14.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist in the FCSP, AMPQ, SCTP, and sFlow
    dissector that could lead to an infinite loop resulting
    in a denial of service. (Bugs 7789, 7802, 8337, 8359)

  - Errors exist in the CIMD, DTLS, Mount, MS-MMS, RTPS,
    and RTPS2 that could allow them to crash.
    (Bugs 8382, 8332, 8335, 8346, 8380)

  - The ACN dissector can attempt a divide by zero
    operation that could lead to an application crash.
    (Bug 8340)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-32.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-33.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-22.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.6.14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.6.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.6.0', 'max_version' : '1.6.13', 'fixed_version' : '1.6.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
