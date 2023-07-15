#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61573);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2012-4285",
    "CVE-2012-4286",
    "CVE-2012-4287",
    "CVE-2012-4288",
    "CVE-2012-4289",
    "CVE-2012-4290",
    "CVE-2012-4291",
    "CVE-2012-4292",
    "CVE-2012-4293",
    "CVE-2012-4294",
    "CVE-2012-4295",
    "CVE-2012-4296",
    "CVE-2012-4297",
    "CVE-2012-4298"
  );
  script_bugtraq_id(55035);

  script_name(english:"Wireshark 1.8.x < 1.8.2 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.8.x before 1.8.2.  This
version is affected by the following vulnerabilities :

  - The 'DCP ETSI' dissector and 'pcap-ng' parser can 
    attempt a divide by zero operation leading to an
    application crash. (CVE-2012-4285, CVE-2012-4286)

  - The 'MongoDB', 'XTP', 'AFP', and 'CTDB' dissectors can
    be caused to large or infinite loops. (CVE-2012-4287,
    CVE-2012-4288, CVE-2012-4289, CVE-2012-4290)

  - The 'CIP' dissector can be caused to exhaust system
    memory. (CVE-2012-4291)

  - The 'STUN' dissector can be caused to crash.
    (CVE-2012-4292)

  - The 'EtherCAT Mailbox' dissector can be caused to
    abort. (CVE-2012-4293)

  - A buffer overflow exists related to the 'ERF', 'RTPS2'
    and 'GSM RLC MAC' dissectors. (CVE-2012-4294,
    CVE-2012-4295, CVE-2012-4296, CVE-2012-4297)

  - A file parsing error related to 'Ixia IxVeriWave'
    processing can allow a buffer overflow. (CVE-2012-4298)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-24.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/17");

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
  { 'min_version' : '1.8.0', 'max_version' : '1.8.1', 'fixed_version' : '1.8.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
