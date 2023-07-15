#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-1959.
##

include('compat.inc');

if (description)
{
  script_id(171828);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2022-36113", "CVE-2022-36114");

  script_name(english:"Amazon Linux 2 : rust (ALAS-2023-1959)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of rust installed on the remote host is prior to 1.66.1-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2023-1959 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-1959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-36113.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-36114.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update rust' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rustfmt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'cargo-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analyzer-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analyzer-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugger-common-1.66.1-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gdb-1.66.1-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-src-1.66.1-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.66.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.66.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cargo / clippy / rust / etc");
}