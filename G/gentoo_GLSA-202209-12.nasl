#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-12.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165446);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/25");

  script_cve_id(
    "CVE-2021-3695",
    "CVE-2021-3696",
    "CVE-2021-3697",
    "CVE-2021-3981",
    "CVE-2022-28733",
    "CVE-2022-28734",
    "CVE-2022-28735",
    "CVE-2022-28736",
    "CVE-2022-28737"
  );

  script_name(english:"GLSA-202209-12 : GRUB: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-12 (GRUB: Multiple Vulnerabilities)

  - A crafted 16-bit grayscale PNG image may lead to a out-of-bounds write in the heap area. An attacker may
    take advantage of that to cause heap data corruption or eventually arbitrary code execution and circumvent
    secure boot protections. This issue has a high complexity to be exploited as an attacker needs to perform
    some triage over the heap layout to achieve signifcant results, also the values written into the memory
    are repeated three times in a row making difficult to produce valid payloads. This flaw affects grub2
    versions prior grub-2.12. (CVE-2021-3695)

  - A heap out-of-bounds write may heppen during the handling of Huffman tables in the PNG reader. This may
    lead to data corruption in the heap space. Confidentiality, Integrity and Availablity impact may be
    considered Low as it's very complex to an attacker control the encoding and positioning of corrupted
    Huffman entries to achieve results such as arbitrary code execution and/or secure boot circumvention. This
    flaw affects grub2 versions prior grub-2.12. (CVE-2021-3696)

  - A crafted JPEG image may lead the JPEG reader to underflow its data pointer, allowing user-controlled data
    to be written in heap. To a successful to be performed the attacker needs to perform some triage over the
    heap layout and craft an image with a malicious format and payload. This vulnerability can lead to data
    corruption and eventual code execution or secure boot circumvention. This flaw affects grub2 versions
    prior grub-2.12. (CVE-2021-3697)

  - A flaw in grub2 was found where its configuration file, known as grub.cfg, is being created with the wrong
    permission set allowing non privileged users to read its content. This represents a low severity
    confidentiality issue, as those users can eventually read any encrypted passwords present in grub.cfg.
    This flaw affects grub2 2.06 and previous versions. This issue has been fixed in grub upstream but no
    version with the fix is currently released. (CVE-2021-3981)

  - grub2: Integer underflow in grub_net_recv_ip4_packets (CVE-2022-28733)

  - grub2: Out-of-bound write when handling split HTTP headers (CVE-2022-28734)

  - grub2: shim_lock verifier allows non-kernel files to be loaded (CVE-2022-28735)

  - grub2: use-after-free in grub_cmd_chainloader() (CVE-2022-28736)

  - shim: Buffer overflow when loading crafted EFI images (CVE-2022-28737)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-12");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835082");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=850535");
  script_set_attribute(attribute:"solution", value:
"All GRUB users should upgrade to the latest version:            # emerge --sync           # emerge --ask --oneshot
--verbose >=sys-boot/grub-2.06-r3          After upgrading, make sure to run the grub-install command with options
appropriate for your system. See the GRUB2 Gentoo Wiki page for directions. Your system will be vulnerable until this
action is performed.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:grub");
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
    'name' : "sys-boot/grub",
    'unaffected' : make_list("ge 2.06", "lt 2.0.0"),
    'vulnerable' : make_list("lt 2.06")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GRUB");
}
