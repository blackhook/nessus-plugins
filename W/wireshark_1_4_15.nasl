#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(61571);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2012-4285",
    "CVE-2012-4288",
    "CVE-2012-4289",
    "CVE-2012-4290",
    "CVE-2012-4291",
    "CVE-2012-4292",
    "CVE-2012-4293",
    "CVE-2012-4296"
  );
  script_bugtraq_id(55035);

  script_name(english:"Wireshark 1.4.x < 1.4.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.4.x before 1.4.15.  This
version is affected by the following vulnerabilities :

  - The 'DCP ETSI' dissector can attempt a divide by zero
    operation leading to an application crash.
    (CVE-2012-4285)

  - The 'XTP', 'AFP', and 'CTDB' dissectors can be caused
    to go into large or infinite loops. (CVE-2012-4288,
    CVE-2012-4289, CVE-2012-4290)

  - The 'CIP' dissector can be caused to exhaust system
    memory. (CVE-2012-4291)

  - The 'STUN' dissector can be caused to crash.
    (CVE-2012-4292)

  - The 'EtherCAT Mailbox' dissector can be caused to
    abort. (CVE-2012-4293)

  - A buffer overflow exists related to the 'RTPS2'
    dissector. (CVE-2012-4296)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.15.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7566");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-13");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7571");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-15");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7603");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7568");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-18");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7570");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-20");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7569");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-21");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7562");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-22");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7573");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-23");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.4.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4296");

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
  { 'min_version' : '1.4.0', 'max_version' : '1.4.14', 'fixed_version' : '1.4.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
