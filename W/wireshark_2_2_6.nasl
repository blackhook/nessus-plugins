#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99437);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2017-7700",
    "CVE-2017-7701",
    "CVE-2017-7702",
    "CVE-2017-7703",
    "CVE-2017-7704",
    "CVE-2017-7705",
    "CVE-2017-7745",
    "CVE-2017-7746",
    "CVE-2017-7747",
    "CVE-2017-7748"
  );
  script_bugtraq_id(
    97627,
    97628,
    97630,
    97631,
    97632,
    97633,
    97634,
    97635,
    97636,
    97638
  );

  script_name(english:"Wireshark 2.0.x < 2.0.12 / 2.2.x < 2.2.6 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.12 or 2.2.x prior to 2.2.6. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - An infinite loop condition condition exists in the
    NetScaler file parser within file wiretap/netscaler.c
    when handling specially crafted capture files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7700)

  - An infinite loop condition condition exists in the BGP
    dissector within file epan/dissectors/packet-bgp.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7701)

  - An infinite loop condition condition exists in the WBXML
    dissector within file epan/dissectors/packet-wbxml.c
    when handling specially crafted packets or trace files.
    An unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7702)

  - A denial of service vulnerability exists in the IMAP
    dissector within file epan/dissectors/packet-imap.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    crash the program. (CVE-2017-7703)

  - An infinite loop condition condition exists in the DOF
    dissector within file epan/dissectors/packet-dof.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. Note that this issue
    only applies to the 2.2.x version. (CVE-2017-7704)

  - An infinite loop condition condition exists in the RPC
    over RDMA dissector within file
    epan/dissectors/packet-rpcrdma.c when handling specially
    crafted packets or trace files. An unauthenticated,
    remote attacker can exploit this to cause excessive
    consumption of CPU resources, resulting in a denial of
    service condition. (CVE-2017-7705)

  - An infinite loop condition condition exists in the
    SIGCOMP dissector within file
    epan/dissectors/packet-sigcomp.c when handling specially
    crafted packets or trace files. An unauthenticated,
    remote attacker can exploit this to cause excessive
    consumption of CPU resources, resulting in a denial of
    service condition. (CVE-2017-7745)

  - An infinite loop condition condition exists in the
    SLSK dissector in the dissect_slsk_pdu() function within
    file epan/dissectors/packet-slsk.c, when handling
    specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7746)

  - An out-of-bounds read error exists in the PacketBB
    dissector in the dissect_pbb_addressblock() function
    within file epan/dissectors/packet-packetbb.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    crash the program. (CVE-2017-7747)

  - An infinite loop condition condition exists in the WSP
    dissector within file epan/dissectors/packet-wsp.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7748)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.6.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.12 / 2.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.2.0', 'max_version' : '2.2.5', 'fixed_version' : '2.2.6' },
  { 'min_version' : '2.0.0', 'max_version' : '2.0.11', 'fixed_version' : '2.0.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
