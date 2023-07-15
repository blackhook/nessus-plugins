#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101898);
  script_version("1.5");
  script_cvs_date("Date: 2018/08/07 16:46:51");

  script_cve_id(
    "CVE-2017-9617",
    "CVE-2017-11406",
    "CVE-2017-11407",
    "CVE-2017-11408",
    "CVE-2017-11409"
  );
  script_bugtraq_id(
    99087
  );

  script_name(english:"Wireshark 2.0.x < 2.0.14 / 2.2.x < 2.2.8 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.14 or 2.2.x prior to 2.2.8. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the DAAP
    dissector, specifically in the dissect_daap_one_tag()
    function within file epan/dissectors/packet-daap.c. An
    unauthenticated, remote attacker can exploit this to
    exhaust stack resources through uncontrolled recursion.
    (CVE-2017-9617)

  - An infinite loop condition exists in the DOCSIS
    dissector, specifically in the dissect_docsis() function
    within file plugins/docsis/packet-docsis.c. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet or packet trace, to consume
    available CPU resources, resulting in a denial of
    service condition. (CVE-2017-11406)

  - A memory allocation issue exists in the MQ dissector,
    specifically in the reassemble_mq() function within file
    epan/dissectors/packet-mq.c, due to improper validation
    of fragment lengths before attempting reassembly. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet or packet trace, to cause a
    denial of service condition. (CVE-2017-11407)

  - A flaw exists in the AMQP dissector, specifically in
    the get_amqp_1_0_value_formatter() function within file
    epan/dissectors/packet-amqp.c, when decoding lists.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted packet or packet trace, to cause
    a stack overflow, resulting in a denial of service
    condition. (CVE-2017-11408)

  - A large loop condition exists in the GPRS LLC dissector,
    specifically in the llc_gprs_dissect_xid() function
    within file epan/dissectors/packet-gprs-llc.c, when
    handling specially crafted packet or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. Note that this
    issue only applies to version 2.0.x. (CVE-2017-11409)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.8.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-34.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-35.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-36.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-37.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13799");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.14 / 2.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Wireshark", win_local:TRUE);

constraints = [
  { "min_version" : "2.0.0", "fixed_version" : "2.0.14" },
  { "min_version" : "2.2.0", "fixed_version" : "2.2.8" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
