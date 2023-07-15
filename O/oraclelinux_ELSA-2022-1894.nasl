##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-1894.
##

include('compat.inc');

if (description)
{
  script_id(161276);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-21658");

  script_name(english:"Oracle Linux 8 : rust-toolset:ol8 (ELSA-2022-1894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-1894 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-1894.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21658");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cargo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-std-static-wasm32-unknown-unknown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-std-static-wasm32-wasi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rustfmt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/rust-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module rust-toolset:ol8');
if ('ol8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module rust-toolset:' + module_ver);

var appstreams = {
    'rust-toolset:ol8': [
      {'reference':'cargo-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-doc-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-debugger-common-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-gdb-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-lldb-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-src-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-unknown-unknown-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-wasm32-wasi-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.58.1-1.module+el8.6.0+20563+1eb4e043', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module rust-toolset:ol8');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cargo / cargo-doc / clippy / etc');
}
