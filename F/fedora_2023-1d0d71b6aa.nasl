#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-1d0d71b6aa
#

include('compat.inc');

if (description)
{
  script_id(176430);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");
  script_xref(name:"FEDORA", value:"2023-1d0d71b6aa");

  script_name(english:"Fedora 37 : rust-buffered-reader / rust-nettle / rust-nettle-sys / etc (2023-1d0d71b6aa)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2023-1d0d71b6aa advisory.

  - - Update the sequoia-openpgp crate to version 1.16.0. - Update the nettle crate to version 7.3.0. - Update
    the nettle-sys crate to version 2.2.0. - Update the buffered-reader crate to version 1.2.0.  Version
    1.16.0 of the sequoia-openpgp crate fixes some issues in parsing code, which could lead to attempted out-
    of-bounds accesses that result in crashes due to bounds checks which are included by default in Rust code.
    This update contains rebuilds of all applications that are based on sequoia-openpgp to address this issue.
    ----  Update to version 1.5.0. This release improves compatibility with the version of librnp that's
    bundled in recent versions of thunderbird.  (FEDORA-2023-1d0d71b6aa)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-1d0d71b6aa");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-buffered-reader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-nettle-sys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rpm-sequoia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-keyring-linter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-octopus-librnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-openpgp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-policy-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-sqv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-sequoia-wot");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'rust-buffered-reader-1.2.0-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-nettle-7.3.0-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-nettle-sys-2.2.0-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rpm-sequoia-1.4.0-3.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-keyring-linter-1.0.1-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-octopus-librnp-1.5.0-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-openpgp-1.16.0-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-policy-config-0.6.0-4.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sop-0.28.0-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sq-0.26.0-8.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-sqv-1.1.0-5.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-sequoia-wot-0.5.0-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rust-buffered-reader / rust-nettle / rust-nettle-sys / etc');
}
