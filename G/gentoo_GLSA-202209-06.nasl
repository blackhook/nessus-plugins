#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165439);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/25");

  script_cve_id(
    "CVE-2022-34612",
    "CVE-2022-36039",
    "CVE-2022-36040",
    "CVE-2022-36041",
    "CVE-2022-36042",
    "CVE-2022-36043",
    "CVE-2022-36044"
  );

  script_name(english:"GLSA-202209-06 : Rizin: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-06 (Rizin: Multiple Vulnerabilities)

  - Rizin v0.4.0 and below was discovered to contain an integer overflow via the function get_long_object().
    This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted binary.
    (CVE-2022-34612)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to out-of-bounds write when parsing DEX files. A user opening a malicious DEX file could be
    affected by this vulnerability, allowing an attacker to execute code on the user's machine. A patch is
    available on the `dev` branch of the repository. (CVE-2022-36039)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when getting data from PYC(python) files. A user opening a malicious
    PYC file could be affected by this vulnerability, allowing an attacker to execute code on the user's
    machine. Commit number 68948017423a12786704e54227b8b2f918c2fd27 contains a patch. (CVE-2022-36040)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when parsing Mach-O files. A user opening a malicious Mach-O file
    could be affected by this vulnerability, allowing an attacker to execute code on the user's machine.
    Commit number 7323e64d68ecccfb0ed3ee480f704384c38676b2 contains a patch. (CVE-2022-36041)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when getting data from dyld cache files. A user opening a malicious
    dyld cache file could be affected by this vulnerability, allowing an attacker to execute code on the
    user's machine. Commit number 556ca2f9eef01ec0f4a76d1fbacfcf3a87a44810 contains a patch. (CVE-2022-36042)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to a double free in bobj.c:rz_bin_reloc_storage_free() when freeing relocations generated from
    qnx binary plugin. A user opening a malicious qnx binary could be affected by this vulnerability, allowing
    an attacker to execute code on the user's machine. Commit number a3d50c1ea185f3f642f2d8180715f82d98840784
    contains a patch for this issue. (CVE-2022-36043)

  - Rizin is a UNIX-like reverse engineering framework and command-line toolset. Versions 0.4.0 and prior are
    vulnerable to an out-of-bounds write when getting data from Luac files. A user opening a malicious Luac
    file could be affected by this vulnerability, allowing an attacker to execute code on the user's machine.
    Commits 07b43bc8aa1ffebd9b68d60624c9610cf7e460c7 and 05bbd147caccc60162d6fba9baaaf24befa281cd contain
    fixes for the issue. (CVE-2022-36044)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=861524");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=868999");
  script_set_attribute(attribute:"solution", value:
"All Rizin users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-util/rizin-0.4.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rizin");
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
    'name' : "dev-util/rizin",
    'unaffected' : make_list("ge 0.4.1", "lt 0.0.0"),
    'vulnerable' : make_list("lt 0.4.1")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Rizin");
}
