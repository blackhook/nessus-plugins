#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66895);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2013-4074",
    "CVE-2013-4075",
    "CVE-2013-4076",
    "CVE-2013-4077",
    "CVE-2013-4078",
    "CVE-2013-4079",
    "CVE-2013-4080",
    "CVE-2013-4081",
    "CVE-2013-4082",
    "CVE-2013-4083"
  );
  script_bugtraq_id(
    60448,
    60495,
    60498,
    60499,
    60500,
    60501,
    60502,
    60503,
    60504,
    60505,
    60506
  );

  script_name(english:"Wireshark 1.8.x < 1.8.8 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.8.  It is,
therefore, affected by the following vulnerabilities :

  - Errors exist in the CAPWAP, DCP ETSI, GSM CBCH, GMR-1 
    BCCH, PPP, NBAP, RDP dissectors that could allow them to
    crash. (Bugs 7664, 7880, 8697, 8717, 8725, 8726, 8727, 
    8729, 8730)

  - An error exists in the Assa Abloy R3 dissector that
    could cause a denial of service, resulting in
    consumption of excessive memory and CPU. (Bug 8764)

  - An error exists in the HTTP dissector that could overrun
    the stack, which could result in an application crash.
    (Bug 8733)

  - An error exists in the Ixia IxVeriWave file parser that
    could overflow the heap, resulting in consumption of
    excessive CPU resources and crash. (Bug 8760)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-32.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-33.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-34.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-35.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-36.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-37.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-38.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-39.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-40.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-41.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.8.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/18");
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
  { 'min_version' : '1.8.0', 'max_version' : '1.8.7', 'fixed_version' : '1.8.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
