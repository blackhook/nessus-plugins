#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76992);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2014-5161",
    "CVE-2014-5162",
    "CVE-2014-5163",
    "CVE-2014-5164",
    "CVE-2014-5165"
  );
  script_bugtraq_id(69000, 69001, 69002, 69003, 69005);

  script_name(english:"Wireshark 1.10.x < 1.10.9 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is version 1.10.x prior to 1.10.9.
It is, therefore, affected by the following vulnerabilities :

  - A buffer underflow flaw exists in the 'dissect_log'
    function of the IrDA dissector, which is triggered when
    handling malformed packets. Using a specially crafted
    packet, a remote attacker could cause a denial of
    service by crashing the application. (CVE-2014-5161)

  - A buffer underflow flaw exists in the 'read_new_line'
    function of the DCT2000 dissector, which is triggered
    when handling malformed packets. Using a specially
    crafted packet, a remote attacker could cause a denial
    of service by crashing the application. (CVE-2014-5162)

  - An APN decode flaw exists in the GTP and GSM Management
    dissectors, which is triggered when handling malformed
    packets. Using a specially crafted packet, a remote
    attacker could cause a denial of service by crashing the
    application. (CVE-2014-5163)

  - An initialization flaw exists in the 'rlc_decode_li'
    function of the RLC dissector, which is triggered when
    handling malformed packets. Using a specially crafted
    packet, a remote attacker could cause a denial of
    service by crashing the application. (CVE-2014-5164)

  - A padding validation flaw exists within the ASN.1 BER
    dissector, which is triggered when handling malformed
    packets. Using a specially crafted packet, a remote
    attacker could cause a denial of service by crashing
    the application. (CVE-2014-5165)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-08.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-09.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-11.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.9.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.10.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.10.0', 'max_version' : '1.10.8', 'fixed_version' : '1.10.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
