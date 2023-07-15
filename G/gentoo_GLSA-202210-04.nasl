#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-04.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166163);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/16");

  script_cve_id(
    "CVE-2021-4181",
    "CVE-2021-4182",
    "CVE-2021-4183",
    "CVE-2021-4184",
    "CVE-2021-4185",
    "CVE-2021-4186",
    "CVE-2021-4190",
    "CVE-2021-22235",
    "CVE-2021-39920",
    "CVE-2021-39921",
    "CVE-2021-39922",
    "CVE-2021-39924",
    "CVE-2021-39925",
    "CVE-2021-39926",
    "CVE-2021-39928",
    "CVE-2021-39929",
    "CVE-2022-0581",
    "CVE-2022-0582",
    "CVE-2022-0583",
    "CVE-2022-0585",
    "CVE-2022-0586"
  );

  script_name(english:"GLSA-202210-04 : Wireshark: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-04 (Wireshark: Multiple Vulnerabilities)

  - Crash in DNP dissector in Wireshark 3.4.0 to 3.4.6 and 3.2.0 to 3.2.14 allows denial of service via packet
    injection or crafted capture file (CVE-2021-22235)

  - NULL pointer exception in the IPPUSB dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service via
    packet injection or crafted capture file (CVE-2021-39920)

  - NULL pointer exception in the Modbus dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39921)

  - Buffer overflow in the C12.22 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39922)

  - Large loop in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39924)

  - Buffer overflow in the Bluetooth SDP dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39925)

  - Buffer overflow in the Bluetooth HCI_ISO dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service
    via packet injection or crafted capture file (CVE-2021-39926)

  - NULL pointer exception in the IEEE 802.11 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39928)

  - Uncontrolled Recursion in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17
    allows denial of service via packet injection or crafted capture file (CVE-2021-39929)

  - Crash in the Sysdig Event dissector in Wireshark 3.6.0 and 3.4.0 to 3.4.10 allows denial of service via
    packet injection or crafted capture file (CVE-2021-4181)

  - Crash in the RFC 7468 dissector in Wireshark 3.6.0 and 3.4.0 to 3.4.10 allows denial of service via packet
    injection or crafted capture file (CVE-2021-4182)

  - Crash in the pcapng file parser in Wireshark 3.6.0 allows denial of service via crafted capture file
    (CVE-2021-4183)

  - Infinite loop in the BitTorrent DHT dissector in Wireshark 3.6.0 and 3.4.0 to 3.4.10 allows denial of
    service via packet injection or crafted capture file (CVE-2021-4184)

  - Infinite loop in the RTMPT dissector in Wireshark 3.6.0 and 3.4.0 to 3.4.10 allows denial of service via
    packet injection or crafted capture file (CVE-2021-4185)

  - Crash in the Gryphon dissector in Wireshark 3.4.0 to 3.4.10 allows denial of service via packet injection
    or crafted capture file (CVE-2021-4186)

  - Large loop in the Kafka dissector in Wireshark 3.6.0 allows denial of service via packet injection or
    crafted capture file (CVE-2021-4190)

  - Crash in the CMS protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of
    service via packet injection or crafted capture file (CVE-2022-0581)

  - Unaligned access in the CSN.1 protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows
    denial of service via packet injection or crafted capture file (CVE-2022-0582)

  - Crash in the PVFS protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of
    service via packet injection or crafted capture file (CVE-2022-0583)

  - Large loops in multiple protocol dissectors in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allow denial
    of service via packet injection or crafted capture file (CVE-2022-0585)

  - Infinite loop in RTMPT protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of
    service via packet injection or crafted capture file (CVE-2022-0586)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-04");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=802216");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=824474");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830343");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833294");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=869140");
  script_set_attribute(attribute:"solution", value:
"All Wireshark users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-analyzer/wireshark-3.6.8");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "net-analyzer/wireshark",
    'unaffected' : make_list("ge 3.6.8", "lt 3.0.0"),
    'vulnerable' : make_list("lt 3.6.8")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Wireshark");
}
