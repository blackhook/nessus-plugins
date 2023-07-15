#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-30.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164113);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

  script_cve_id(
    "CVE-2021-3487",
    "CVE-2021-3530",
    "CVE-2021-3549",
    "CVE-2021-20197",
    "CVE-2021-20284",
    "CVE-2021-20294",
    "CVE-2021-45078"
  );

  script_name(english:"GLSA-202208-30 : GNU Binutils: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-30 (GNU Binutils: Multiple Vulnerabilities)

  - There is an open race window when writing output in the following utilities in GNU binutils version 2.35
    and earlier:ar, objcopy, strip, ranlib. When these utilities are run as a privileged user (presumably as
    part of a script updating binaries across different users), an unprivileged user can trick these utilities
    into getting ownership of arbitrary files through a symlink. (CVE-2021-20197)

  - A flaw was found in GNU Binutils 2.35.1, where there is a heap-based buffer overflow in
    _bfd_elf_slurp_secondary_reloc_section in elf.c due to the number of symbols not calculated correctly. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20284)

  - A flaw was found in binutils readelf 2.35 program. An attacker who is able to convince a victim using
    readelf to read a crafted file could trigger a stack buffer overflow, out-of-bounds write of arbitrary
    data supplied by the attacker. The highest impact of this flaw is to confidentiality, integrity, and
    availability. (CVE-2021-20294)

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

  - A flaw was discovered in GNU libiberty within demangle_path() in rust-demangle.c, as distributed in GNU
    Binutils version 2.36. A crafted symbol can cause stack memory to be exhausted leading to a crash.
    (CVE-2021-3530)

  - An out of bounds flaw was found in GNU binutils objdump utility version 2.36. An attacker could use this
    flaw and pass a large section to avr_elf32_load_records_from_section() probably resulting in a crash or in
    some cases memory corruption. The highest threat from this vulnerability is to integrity as well as system
    availability. (CVE-2021-3549)

  - stab_xcoff_builtin_type in stabs.c in GNU Binutils through 2.37 allows attackers to cause a denial of
    service (heap-based buffer overflow) or possibly have unspecified other impact, as demonstrated by an out-
    of-bounds write. NOTE: this issue exists because of an incorrect fix for CVE-2018-12699. (CVE-2021-45078)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-30");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=778545");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=792342");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829304");
  script_set_attribute(attribute:"solution", value:
"All Binutils users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-devel/binutils-2.38
        
All Binutils library users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-libs/binutils-libs-2.38");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:binutils-libs");
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
    'name' : "sys-devel/binutils",
    'unaffected' : make_list("ge 2.38"),
    'vulnerable' : make_list("lt 2.38")
  },
  {
    'name' : "sys-libs/binutils-libs",
    'unaffected' : make_list("ge 2.38"),
    'vulnerable' : make_list("lt 2.38")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


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
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU Binutils");
}
