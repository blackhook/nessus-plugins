#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:3063.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157792);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2020-36323",
    "CVE-2021-28875",
    "CVE-2021-28876",
    "CVE-2021-28877",
    "CVE-2021-28878",
    "CVE-2021-28879",
    "CVE-2021-31162"
  );
  script_xref(name:"RLSA", value:"2021:3063");

  script_name(english:"Rocky Linux 8 : rust-toolset:rhel8 (RLSA-2021:3063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:3063 advisory.

  - In the standard library in Rust before 1.52.0, there is an optimization for joining strings that can cause
    uninitialized bytes to be exposed (or the program to crash) if the borrowed string changes after its
    length is checked. (CVE-2020-36323)

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

  - In the standard library in Rust before 1.52.0, a double free can occur in the Vec::from_iter function if
    freeing the element panics. (CVE-2021-31162)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:3063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1950396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1950398");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cargo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cargo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clippy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rust-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rustfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rustfmt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'cargo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-doc-1.52.1-1.module+el8.4.0+641+ca238f88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rls-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugger-common-1.52.1-1.module+el8.4.0+641+ca238f88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugsource-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugsource-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gdb-1.52.1-1.module+el8.4.0+641+ca238f88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-lldb-1.52.1-1.module+el8.4.0+641+ca238f88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-src-1.52.1-1.module+el8.4.0+641+ca238f88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-debuginfo-1.52.1-1.module+el8.4.0+641+ca238f88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cargo / cargo-debuginfo / cargo-doc / clippy / clippy-debuginfo / rls / etc');
}
