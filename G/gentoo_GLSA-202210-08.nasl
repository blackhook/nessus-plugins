#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-08.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166164);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/16");

  script_cve_id(
    "CVE-2021-45386",
    "CVE-2021-45387",
    "CVE-2022-27416",
    "CVE-2022-27418",
    "CVE-2022-27939",
    "CVE-2022-27940",
    "CVE-2022-27941",
    "CVE-2022-27942",
    "CVE-2022-28487",
    "CVE-2022-37047",
    "CVE-2022-37048",
    "CVE-2022-37049"
  );

  script_name(english:"GLSA-202210-08 : Tcpreplay: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-08 (Tcpreplay: Multiple Vulnerabilities)

  - tcpreplay 4.3.4 has a Reachable Assertion in add_tree_ipv6() at tree.c (CVE-2021-45386)

  - tcpreplay 4.3.4 has a Reachable Assertion in add_tree_ipv4() at tree.c. (CVE-2021-45387)

  - Tcpreplay v4.4.1 was discovered to contain a double-free via __interceptor_free. (CVE-2022-27416)

  - Tcpreplay v4.4.1 has a heap-based buffer overflow in do_checksum_math at /tcpedit/checksum.c.
    (CVE-2022-27418)

  - tcprewrite in Tcpreplay 4.4.1 has a reachable assertion in get_layer4_v6 in common/get.c. (CVE-2022-27939)

  - tcprewrite in Tcpreplay 4.4.1 has a heap-based buffer over-read in get_ipv6_next in common/get.c.
    (CVE-2022-27940)

  - tcprewrite in Tcpreplay 4.4.1 has a heap-based buffer over-read in get_l2len_protocol in common/get.c.
    (CVE-2022-27941)

  - tcpprep in Tcpreplay 4.4.1 has a heap-based buffer over-read in parse_mpls in common/get.c.
    (CVE-2022-27942)

  - Tcpreplay version 4.4.1 contains a memory leakage flaw in fix_ipv6_checksums() function. The highest
    threat from this vulnerability is to data confidentiality. (CVE-2022-28487)

  - The component tcprewrite in Tcpreplay v4.4.1 was discovered to contain a heap-based buffer overflow in
    get_ipv6_next at common/get.c:713. NOTE: this is different from CVE-2022-27940. (CVE-2022-37047)

  - The component tcprewrite in Tcpreplay v4.4.1 was discovered to contain a heap-based buffer overflow in
    get_l2len_protocol at common/get.c:344. NOTE: this is different from CVE-2022-27941. (CVE-2022-37048)

  - The component tcpprep in Tcpreplay v4.4.1 was discovered to contain a heap-based buffer overflow in
    parse_mpls at common/get.c:150. NOTE: this is different from CVE-2022-27942. (CVE-2022-37049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-08");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833139");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836240");
  script_set_attribute(attribute:"solution", value:
"All Tcpreplay users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-analyzer/tcpreplay-4.4.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27942");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tcpreplay");
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
    'name' : "net-analyzer/tcpreplay",
    'unaffected' : make_list("ge 4.4.2", "lt 4.0.0"),
    'vulnerable' : make_list("lt 4.4.2")
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
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Tcpreplay");
}
