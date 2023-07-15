#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91820);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2016-5350",
    "CVE-2016-5351",
    "CVE-2016-5353",
    "CVE-2016-5354",
    "CVE-2016-5355",
    "CVE-2016-5356",
    "CVE-2016-5357",
    "CVE-2016-5359"
  );

  script_name(english:"Wireshark 1.12.x < 1.12.12 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.12. It is, therefore, affected by multiple denial
of service vulnerabilities :

  - An infinite loop exists in the SPOOLs dissector. A
    remote attacker, via a specially crafted packet or trace
    file, can exploit this to exhaust CPU resources,
    resulting in a denial of service condition.
    (CVE-2016-5350)

  - A flaw exists in the IEEE 802.11 dissector that is
    triggered when handling a malformed packet or trace
    file. A remote attacker can exploit this to cause a
    denial of service condition. (CVE-2016-5351)

  - A flaw exists in the UMTS FP dissector that is triggered
    when handling a malformed packet or trace file. A remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-5353)

  - A flaw exists in multiple USB dissectors that is
    triggered when a handling malformed packet or trace
    file. A remote attacker can exploit this to cause a
    denial of service condition. (CVE-2016-5354)

  - A flaw exists in the Toshiba file parser that is
    triggered when handling a malformed packet trace file. A
    remote attacker can exploit this, by convincing a user
    to open a specially crafted packet trace file, to cause
    a denial of service condition. (CVE-2016-5355)

  - A flaw exists in the CoSine file parser that is
    triggered when handling a malformed packet trace file. A
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2016-5356)

  - A flaw exists in the NetScreen file parser that is
    triggered when handling a malformed packet trace file. A
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2016-5357)

  - An integer overflow condition exists in the WBXML
    dissector. A remote attacker can exploit this, via a
    specially crafted packet or trace file, to exhaust CPU
    resources, resulting in a denial of service condition.
    (CVE-2016-5359)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-29.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-30.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-32.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-33.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-34.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-35.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-36.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-38.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.12.0', 'max_version' : '1.12.11', 'fixed_version' : '1.12.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
