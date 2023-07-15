#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-09.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166161);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/16");

  script_cve_id(
    "CVE-2021-28875",
    "CVE-2021-28876",
    "CVE-2021-28877",
    "CVE-2021-28878",
    "CVE-2021-28879",
    "CVE-2021-29922",
    "CVE-2021-31162",
    "CVE-2021-36317",
    "CVE-2021-36318",
    "CVE-2021-42574",
    "CVE-2021-42694",
    "CVE-2022-21658",
    "CVE-2022-36113",
    "CVE-2022-36114"
  );

  script_name(english:"GLSA-202210-09 : Rust: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-09 (Rust: Multiple Vulnerabilities)

  - In the standard library in Rust before 1.50.0, read_to_end() does not validate the return value from Read
    in an unsafe context. This bug could lead to a buffer overflow. (CVE-2021-28875)

  - In the standard library in Rust before 1.52.0, the Zip implementation has a panic safety issue. It calls
    __iterator_get_unchecked() more than once for the same index when the underlying iterator panics (in
    certain conditions). This bug could lead to a memory safety violation due to an unmet safety requirement
    for the TrustedRandomAccess trait. (CVE-2021-28876)

  - In the standard library in Rust before 1.51.0, the Zip implementation calls __iterator_get_unchecked() for
    the same index more than once when nested. This bug can lead to a memory safety violation due to an unmet
    safety requirement for the TrustedRandomAccess trait. (CVE-2021-28877)

  - In the standard library in Rust before 1.52.0, the Zip implementation calls __iterator_get_unchecked()
    more than once for the same index (under certain conditions) when next_back() and next() are used
    together. This bug could lead to a memory safety violation due to an unmet safety requirement for the
    TrustedRandomAccess trait. (CVE-2021-28878)

  - In the standard library in Rust before 1.52.0, the Zip implementation can report an incorrect size due to
    an integer overflow. This bug can lead to a buffer overflow when a consumed Zip iterator is used again.
    (CVE-2021-28879)

  - library/std/src/net/parser.rs in Rust before 1.53.0 does not properly consider extraneous zero characters
    at the beginning of an IP address string, which (in some situations) allows attackers to bypass access
    control that is based on IP addresses, because of unexpected octal interpretation. (CVE-2021-29922)

  - In the standard library in Rust before 1.52.0, a double free can occur in the Vec::from_iter function if
    freeing the element panics. (CVE-2021-31162)

  - Dell EMC Avamar Server version 19.4 contains a plain-text password storage vulnerability in AvInstaller. A
    local attacker could potentially exploit this vulnerability, leading to the disclosure of certain user
    credentials. The attacker may be able to use the exposed credentials to access the vulnerable application
    with privileges of the compromised account. (CVE-2021-36317)

  - Dell EMC Avamar versions 18.2,19.1,19.2,19.3,19.4 contain a plain-text password storage vulnerability. A
    high privileged user could potentially exploit this vulnerability, leading to a complete outage.
    (CVE-2021-36318)

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

  - ** DISPUTED ** An issue was discovered in the character definitions of the Unicode Specification through
    14.0. The specification allows an adversary to produce source code identifiers such as function names
    using homoglyphs that render visually identical to a target identifier. Adversaries can leverage this to
    inject code via adversarial identifier definitions in upstream software dependencies invoked deceptively
    in downstream software. NOTE: the Unicode Consortium offers the following alternative approach to
    presenting this concern. An issue is noted in the nature of international text that can affect
    applications that implement support for The Unicode Standard (all versions). Unless mitigated, an
    adversary could produce source code identifiers using homoglyph characters that render visually identical
    to but are distinct from a target identifier. In this way, an adversary could inject adversarial
    identifier definitions in upstream software that are not detected by human reviewers and are invoked
    deceptively in downstream software. The Unicode Consortium has documented this class of security
    vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode
    Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard
    #39, Unicode Security Mechanisms. (CVE-2021-42694)

  - Rust is a multi-paradigm, general-purpose programming language designed for performance and safety,
    especially safe concurrency. The Rust Security Response WG was notified that the `std::fs::remove_dir_all`
    standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker
    could use this security issue to trick a privileged program into deleting files and directories the
    attacker couldn't otherwise access or delete. Rust 1.0.0 through Rust 1.58.0 is affected by this
    vulnerability with 1.58.1 containing a patch. Note that the following build targets don't have usable APIs
    to properly mitigate the attack, and are thus still vulnerable even with a patched toolchain: macOS before
    version 10.10 (Yosemite) and REDOX. We recommend everyone to update to Rust 1.58.1 as soon as possible,
    especially people developing programs expected to run in privileged contexts (including system daemons and
    setuid binaries), as those have the highest risk of being affected by this. Note that adding checks in
    your codebase before calling remove_dir_all will not mitigate the vulnerability, as they would also be
    vulnerable to race conditions like remove_dir_all itself. The existing mitigation is working as intended
    outside of race conditions. (CVE-2022-21658)

  - Cargo is a package manager for the rust programming language. After a package is downloaded, Cargo
    extracts its source code in the ~/.cargo folder on disk, making it available to the Rust projects it
    builds. To record when an extraction is successful, Cargo writes ok to the .cargo-ok file at the root of
    the extracted source code once it extracted all the files. It was discovered that Cargo allowed packages
    to contain a .cargo-ok symbolic link, which Cargo would extract. Then, when Cargo attempted to write ok
    into .cargo-ok, it would actually replace the first two bytes of the file the symlink pointed to with ok.
    This would allow an attacker to corrupt one file on the machine using Cargo to extract the package. Note
    that by design Cargo allows code execution at build time, due to build scripts and procedural macros. The
    vulnerabilities in this advisory allow performing a subset of the possible damage in a harder to track
    down way. Your dependencies must still be trusted if you want to be protected from attacks, as it's
    possible to perform the same attacks with build scripts and procedural macros. The vulnerability is
    present in all versions of Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it.
    Since the vulnerability is just a more limited way to accomplish what a malicious build scripts or
    procedural macros can do, we decided not to publish Rust point releases backporting the security fix.
    Patch files are available for Rust 1.63.0 are available in the wg-security-response repository for people
    building their own toolchain. Mitigations We recommend users of alternate registries to exercise care in
    which package they download, by only including trusted dependencies in their projects. Please note that
    even with these vulnerabilities fixed, by design Cargo allows arbitrary code execution at build time
    thanks to build scripts and procedural macros: a malicious dependency will be able to cause damage
    regardless of these vulnerabilities. crates.io implemented server-side checks to reject these kinds of
    packages years ago, and there are no packages on crates.io exploiting these vulnerabilities. crates.io
    users still need to exercise care in choosing their dependencies though, as remote code execution is
    allowed by design there as well. (CVE-2022-36113)

  - Cargo is a package manager for the rust programming language. It was discovered that Cargo did not limit
    the amount of data extracted from compressed archives. An attacker could upload to an alternate registry a
    specially crafted package that extracts way more data than its size (also known as a zip bomb),
    exhausting the disk space on the machine using Cargo to download the package. Note that by design Cargo
    allows code execution at build time, due to build scripts and procedural macros. The vulnerabilities in
    this advisory allow performing a subset of the possible damage in a harder to track down way. Your
    dependencies must still be trusted if you want to be protected from attacks, as it's possible to perform
    the same attacks with build scripts and procedural macros. The vulnerability is present in all versions of
    Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it. Since the vulnerability is
    just a more limited way to accomplish what a malicious build scripts or procedural macros can do, we
    decided not to publish Rust point releases backporting the security fix. Patch files are available for
    Rust 1.63.0 are available in the wg-security-response repository for people building their own toolchain.
    We recommend users of alternate registries to excercise care in which package they download, by only
    including trusted dependencies in their projects. Please note that even with these vulnerabilities fixed,
    by design Cargo allows arbitrary code execution at build time thanks to build scripts and procedural
    macros: a malicious dependency will be able to cause damage regardless of these vulnerabilities. crates.io
    implemented server-side checks to reject these kinds of packages years ago, and there are no packages on
    crates.io exploiting these vulnerabilities. crates.io users still need to excercise care in choosing their
    dependencies though, as the same concerns about build scripts and procedural macros apply here.
    (CVE-2022-36114)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=782367");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807052");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=821157");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831638");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=870166");
  script_set_attribute(attribute:"solution", value:
"All Rust users should upgrade to the latest version:            # emerge --sync           # emerge --ask --oneshot
--verbose >=dev-lang/rust-1.63.0-r1          All Rust binary users should upgrade to the latest version:            #
emerge --sync           # emerge --ask --oneshot --verbose >=dev-lang/rust-bin-1.64.0          In addition, users using
Portage 3.0.38 or later should ensure that packages with Rust binaries have no vulnerable code statically linked into
their binaries by rebuilding the @rust-rebuild set:            # emerge --ask --oneshot --verbose @rust-rebuild");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rust-bin");
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
    'name' : "dev-lang/rust",
    'unaffected' : make_list("ge 1.63.0-r1", "lt 1.0.0"),
    'vulnerable' : make_list("lt 1.63.0-r1")
  },
  {
    'name' : "dev-lang/rust-bin",
    'unaffected' : make_list("ge 1.64.0", "lt 1.0.0"),
    'vulnerable' : make_list("lt 1.64.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Rust");
}
