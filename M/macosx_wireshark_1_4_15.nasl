#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176397);
  script_version("1.0");
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
  script_xref(name:"IAVB", value:"2012-B-0078-S");

  script_name(english:"Wireshark 1.4.x < 1.4.15 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 1.4.15. It is, therefore, affected by
multiple vulnerabilities as referenced in the wireshark-1.4.15 advisory.

  - The dissect_pft function in epan/dissectors/packet-dcp-etsi.c in the DCP ETSI dissector in Wireshark 1.4.x
    before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows remote attackers to cause a denial of
    service (divide-by-zero error and application crash) via a zero-length message. (CVE-2012-4285)

  - Integer overflow in the dissect_xtp_ecntl function in epan/dissectors/packet-xtp.c in the XTP dissector in
    Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows remote attackers to
    cause a denial of service (loop or application crash) via a large value for a span length. (CVE-2012-4288)

  - epan/dissectors/packet-afp.c in the AFP dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10,
    and 1.8.x before 1.8.2 allows remote attackers to cause a denial of service (loop and CPU consumption) via
    a large number of ACL entries. (CVE-2012-4289)

  - Buffer overflow in epan/dissectors/packet-rtps2.c in the RTPS2 dissector in Wireshark 1.4.x before 1.4.15,
    1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows remote attackers to cause a denial of service (CPU
    consumption) via a malformed packet. (CVE-2012-4296)

  - The CIP dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows
    remote attackers to cause a denial of service (memory consumption) via a malformed packet. (CVE-2012-4291)

  - The dissect_stun_message function in epan/dissectors/packet-stun.c in the STUN dissector in Wireshark
    1.4.x before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 does not properly interact with key-
    destruction behavior in a certain tree library, which allows remote attackers to cause a denial of service
    (application crash) via a malformed packet. (CVE-2012-4292)

  - plugins/ethercat/packet-ecatmb.c in the EtherCAT Mailbox dissector in Wireshark 1.4.x before 1.4.15, 1.6.x
    before 1.6.10, and 1.8.x before 1.8.2 does not properly handle certain integer fields, which allows remote
    attackers to cause a denial of service (application exit) via a malformed packet. (CVE-2012-4293)

  - The CTDB dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows
    remote attackers to cause a denial of service (loop and CPU consumption) via a malformed packet.
    (CVE-2012-4290)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4296");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Wireshark');

var constraints = [
  { 'min_version' : '1.4.0', 'max_version' : '1.4.14', 'fixed_version' : '1.4.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
