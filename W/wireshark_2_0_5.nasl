#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92817);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2016-6503",
    "CVE-2016-6505",
    "CVE-2016-6506",
    "CVE-2016-6508",
    "CVE-2016-6509",
    "CVE-2016-6510",
    "CVE-2016-6511",
    "CVE-2016-6512",
    "CVE-2016-6513"
  );
  script_bugtraq_id(
    92162,
    92163,
    92165,
    92166,
    92168,
    92169,
    92172,
    92173,
    92174
  );
  script_xref(name:"EDB-ID", value:"40195");
  script_xref(name:"EDB-ID", value:"40196");
  script_xref(name:"EDB-ID", value:"40197");
  script_xref(name:"EDB-ID", value:"40198");
  script_xref(name:"EDB-ID", value:"40199");

  script_name(english:"Wireshark 2.0.x < 2.0.5 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.5. It is, therefore, affected by multiple denial of
service vulnerabilities :

  - A denial of service vulnerability exists in the CORBA
    IDL dissector due to improper handling of packets. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet or packet trace file, to cause
    an application crash. Note that this vulnerability only
    affects 64-bit versions of Windows. (CVE-2016-6503)

  - A denial of service vulnerability exists due to a
    divide-by-zero flaw in the dissect_pbb_tlvblock()
    function in packet-packetbb.c. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause an
    application crash. (CVE-2016-6505)

  - A flaw exists in the add_headers() function in
    packet_wsp.c that is triggered when an offset of zero is
    returned by the wkh_content_disposition() function. An
    unauthenticated, remote attacker can exploit this, via a 
    specially crafted packet or packet trace file, to cause
    an infinite loop, resulting in a denial of service
    condition. (CVE-2016-6506)

  - A denial of service vulnerability exists due to an
    incorrect integer data type used in the rlc_decode_li()
    function in packet-rlc.c. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet or packet trace file, to cause a long loop and
    excessive CPU resource consumption, resulting in a
    denial of service condition. (CVE-2016-6508)

  - A denial of service vulnerability exists in the
    dissect_ldss_transfer() function in packet-ldss.c that
    is triggered when recreating a conversation that already
    exists. An unauthenticated, remote attacker can exploit
    this, via a specially crafted packet or packet trace
    file, to cause an application crash. (CVE-2016-6509)

  - An overflow condition exists in the rlc_decode_li()
    function in packet-rlc.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted packet or
    packet trace file, to cause a stack-based buffer
    overflow, resulting in a denial of service condition.
    (CVE-2016-6510)

  - A denial of service vulnerability exists in the
    proto_tree_add_text_valist_internal() function in
    proto.c due to improper handling of packets. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet or packet trace file, to cause
    a long loop and excessive CPU resource consumption.
    (CVE-2016-6511)

  - Multiple flaws exist in the MMSE, WAP, WBXML, and WSP
    dissectors due to improper handling of packets. An
    unauthenticated, remote attacker can exploit these
    issues, via a specially crafted packet or packet trace
    file, to cause an infinite loop, resulting in a denial
    of service condition. (CVE-2016-6512)

  - A denial of service vulnerability exists in the
    parse_wbxml_tag_defined() function in packet-wbxml.c due
    to improper handling of packets. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause an
    application crash. (CVE-2016-6513)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-39.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-41.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-42.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-44.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-45.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-46.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-47.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-48.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-49.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6513");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

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
  { 'min_version' : '2.0.0', 'max_version' : '2.0.4', 'fixed_version' : '2.0.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
