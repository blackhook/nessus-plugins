#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1935.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149927);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2020-36317", "CVE-2020-36318");

  script_name(english:"Oracle Linux 8 : rust-toolset:ol8 (ELSA-2021-1935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-1935 advisory.

  - In the standard library in Rust before 1.49.0, String::retain() function has a panic safety problem. It
    allows creation of a non-UTF-8 Rust string when the provided closure panics. This bug could result in a
    memory safety violation when other string APIs assume that UTF-8 encoding is used on the same string.
    (CVE-2020-36317)

  - In the standard library in Rust before 1.49.0, VecDeque::make_contiguous has a bug that pops the same
    element more than once under certain condition. This bug could result in a use-after-free or double free.
    (CVE-2020-36318)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1935.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rust-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rustfmt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/rust-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module rust-toolset:ol8');
if ('ol8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module rust-toolset:' + module_ver);

appstreams = {
    'rust-toolset:ol8': [
      {'reference':'cargo-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cargo-doc-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clippy-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rls-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-analysis-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-debugger-common-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-doc-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-gdb-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-lldb-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-src-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-std-static-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rustfmt-1.49.0-1.module+el8.4.0+20083+9f8f961d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cargo / cargo-doc / clippy / etc');
}
