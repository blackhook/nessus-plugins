#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95435);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2016-9372",
    "CVE-2016-9373",
    "CVE-2016-9374",
    "CVE-2016-9375",
    "CVE-2016-9376"
  );
script_bugtraq_id(
    94368,
    94369
  );

  script_name(english:"Wireshark 2.0.x < 2.0.8 / 2.2.x < 2.2.2 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.8 or 2.2.x prior to 2.2.2. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - A flaw exists in the dissect_PNIO_C_SDU_RTC1() function
    in packet-pn-rtc-one.c that causes excessive looping. An 
    unauthenticated, remote attacker can exploit this, via
    specially crafted network traffic or a specially crafted
    capture file, to exhaust available resources. Note that
    this vulnerability only affects 2.2.x versions.
    (CVE-2016-9372)

  - A use-after-free error exists in the DCEPRC dissector
    due to improper handling of IA5 SMS decoding. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted network traffic or a specially crafted
    capture file, to cause the application to crash.
    (CVE-2016-9373)

  - A buffer over-read flaw exists in the AllJoyn dissector
    due to improper handling of signature lengths. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted network traffic or a specially crafted
    capture file, to cause the application to crash.
    (CVE-2016-9374)

  - A flaw exists in the DTN dissector in the
    display_metadata_block() function due to improper SDNV
    evaluation. An unauthenticated, remote attacker can
    exploit this, via specially crafted network traffic or a
    specially crafted capture file, to cause an infinite
    loop. (CVE-2016-9375)

  - Multiple flaws exist in the OpenFlow dissector in
    packet-openflow_v5.c due to improper handling of too
    short data lengths. An unauthenticated, remote attacker
    can exploit this, via specially crafted network traffic
    or a specially crafted capture file, to cause the
    application to crash. (CVE-2016-9376)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-58.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-59.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-60.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-61.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-62.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.8 / 2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.2.0', 'max_version' : '2.2.1', 'fixed_version' : '2.2.2' },
  { 'min_version' : '2.0.0', 'max_version' : '2.0.7', 'fixed_version' : '2.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
