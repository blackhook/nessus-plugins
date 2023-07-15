#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100670);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/14  1:59:37");

  script_cve_id(
    "CVE-2017-9343",
    "CVE-2017-9344",
    "CVE-2017-9345",
    "CVE-2017-9346",
    "CVE-2017-9347",
    "CVE-2017-9348",
    "CVE-2017-9349",
    "CVE-2017-9350",
    "CVE-2017-9351",
    "CVE-2017-9352",
    "CVE-2017-9353",
    "CVE-2017-9354"
  );
  script_bugtraq_id(
    98796,
    98797,
    98798,
    98799,
    98800,
    98801,
    98802,
    98803,
    98804,
    98805,
    98806,
    98808
  );

  script_name(english:"Wireshark 2.0.x < 2.0.13 / 2.2.x < 2.2.7 Multiple DoS (macOS)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS or Mac OS X
host is 2.0.x prior to 2.0.13 or 2.2.x prior to 2.2.7. It is,
therefore, affected by multiple denial of service vulnerabilities :

  - A NULL pointer dereference flaw exists in the
    dissect_msnip() function within file
    epan/dissectors/packet-msnip.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause a denial
    of service condition. (CVE-2017-9343)

  - A divide-by-zero error exists in the
    dissect_connparamrequest() function within file
    epan/dissectors/packet-btl2cap.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause a denial
    of service condition. (CVE-2017-9344)

  - An infinite loop condition exists in the
    expand_dns_name() function within file
    epan/dissectors/packet-dns.c when handling packets or
    packet trace files. An unauthenticated, remote attacker
    can exploit this, via a specially crafted packet or
    packet trace file, to consume excessive CPU resources,
    resulting in a denial of service condition.
    (CVE-2017-9345)

  - An infinite loop condition exists in the
    dissect_slsk_pdu() function within file
    epan/dissectors/packet-slsk.c when handling packets or
    packet trace files. An unauthenticated, remote attacker
    can exploit this, via a specially crafted packet or
    packet trace file, to consume excessive CPU resources,
    resulting in a denial of service condition.
    (CVE-2017-9346)

  - A NULL pointer dereference flaw exists in the
    ros_try_string() function within file
    epan/dissectors/asn1/ros/packet-ros-template.c due to
    improper validation of user-supplied input passed as an
    OID string. An unauthenticated, remote attacker can
    exploit this, via a specially crafted packet or packet
    trace file, to cause a denial of service condition. This
    issue only affects version 2.2.x. (CVE-2017-9347)

  - An out-of-bounds read error exists in the
    OALMarshal_UncompressValue() function within file
    epan/dissectors/packet-dof.c when handling Distributed
    Object Framework (DOF) packets. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause a denial
    of service condition. This issue only affects version
    2.2.x. (CVE-2017-9348)

  - An infinite loop condition exists in the
    dissect_dcm_pdu_data() function within file
    epan/dissectors/packet-dcm.c when handling packets or
    packet trace files. An unauthenticated, remote attacker
    can exploit this, via a specially crafted packet or
    packet trace file, to consume excessive CPU resources,
    resulting in a denial of service condition.
    (CVE-2017-9349)

  - A memory allocation issue exists in the
    dissect_opensafety_ssdo_message() function within file
    epan/dissectors/packet-opensafety.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause a denial
    of service condition. (CVE-2017-9350)

  - An out-of-bounds read error exists in the bootp_option()
    function within file epan/dissectors/packet-bootp.c when
    handling vendor class identifier strings in bootp
    packets due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, via a specially crafted packet or packet trace
    file, to cause a denial of service condition.
    (CVE-2017-9351)

  - An infinite loop condition exists in the
    get_bzr_pdu_len() function within file
    epan/dissectors/packet-bzr.c when handling packets or
    packet trace files. An unauthenticated, remote attacker
    can exploit this, via a specially crafted packet or
    packet trace file, to consume excessive CPU resources,
    resulting in a denial of service condition.
    (CVE-2017-9352)

  - A NULL pointer dereference flaw exists in the
    dissect_routing6_rpl() function within file
    epan/dissectors/packet-ipv6.c due to improper validation
    of user-supplied input. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet or packet trace file, to cause a denial of
    service condition. This issue only affects version
    2.2.x. (CVE-2017-9353)

  - A NULL pointer dereference flaw exists in the
    dissect_rgmp() function within file
    epan/dissectors/packet-rgmp.c due to improper validation
    of user-supplied input. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet or packet trace file, to cause a denial of
    service condition. (CVE-2017-9354)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-33.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-32.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-31.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-30.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-29.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-28.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-27.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-26.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-25.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-24.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-23.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.13 / 2.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}


include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

app_info = vcf::get_app_info(app:"Wireshark");

constraints = [
  { "min_version" : "2.0.0", "fixed_version" : "2.0.13" },
  { "min_version" : "2.2.0", "fixed_version" : "2.2.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
