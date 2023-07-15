##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-0557.
##

include('compat.inc');

if (description)
{
  script_id(146583);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-12723");

  script_name(english:"Oracle Linux 8 : perl (ELSA-2021-0557)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-0557 advisory.

  - regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of
    recursive S_study_chunk calls. (CVE-2020-12723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-0557.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12723");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Net-Ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-utils");
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

pkgs = [
    {'reference':'perl-5.26.3-417.el8_3', 'cpu':'aarch64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-5.26.3-417.el8_3', 'cpu':'x86_64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-Attribute-Handlers-0.99-417.el8_3', 'release':'8'},
    {'reference':'perl-devel-5.26.3-417.el8_3', 'cpu':'aarch64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-devel-5.26.3-417.el8_3', 'cpu':'i686', 'release':'8', 'epoch':'4'},
    {'reference':'perl-devel-5.26.3-417.el8_3', 'cpu':'x86_64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-Devel-Peek-1.26-417.el8_3', 'cpu':'aarch64', 'release':'8'},
    {'reference':'perl-Devel-Peek-1.26-417.el8_3', 'cpu':'x86_64', 'release':'8'},
    {'reference':'perl-Devel-SelfStubber-1.06-417.el8_3', 'release':'8'},
    {'reference':'perl-Errno-1.28-417.el8_3', 'cpu':'aarch64', 'release':'8'},
    {'reference':'perl-Errno-1.28-417.el8_3', 'cpu':'x86_64', 'release':'8'},
    {'reference':'perl-ExtUtils-Embed-1.34-417.el8_3', 'release':'8'},
    {'reference':'perl-ExtUtils-Miniperl-1.06-417.el8_3', 'release':'8'},
    {'reference':'perl-interpreter-5.26.3-417.el8_3', 'cpu':'aarch64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-interpreter-5.26.3-417.el8_3', 'cpu':'x86_64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-IO-1.38-417.el8_3', 'cpu':'aarch64', 'release':'8'},
    {'reference':'perl-IO-1.38-417.el8_3', 'cpu':'x86_64', 'release':'8'},
    {'reference':'perl-IO-Zlib-1.10-417.el8_3', 'release':'8', 'epoch':'1'},
    {'reference':'perl-libnetcfg-5.26.3-417.el8_3', 'release':'8', 'epoch':'4'},
    {'reference':'perl-libs-5.26.3-417.el8_3', 'cpu':'aarch64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-libs-5.26.3-417.el8_3', 'cpu':'i686', 'release':'8', 'epoch':'4'},
    {'reference':'perl-libs-5.26.3-417.el8_3', 'cpu':'x86_64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-Locale-Maketext-Simple-0.21-417.el8_3', 'release':'8', 'epoch':'1'},
    {'reference':'perl-macros-5.26.3-417.el8_3', 'cpu':'aarch64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-macros-5.26.3-417.el8_3', 'cpu':'x86_64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-Math-Complex-1.59-417.el8_3', 'release':'8'},
    {'reference':'perl-Memoize-1.03-417.el8_3', 'release':'8'},
    {'reference':'perl-Module-Loaded-0.08-417.el8_3', 'release':'8', 'epoch':'1'},
    {'reference':'perl-Net-Ping-2.55-417.el8_3', 'release':'8'},
    {'reference':'perl-open-1.11-417.el8_3', 'release':'8'},
    {'reference':'perl-Pod-Html-1.22.02-417.el8_3', 'release':'8'},
    {'reference':'perl-SelfLoader-1.23-417.el8_3', 'release':'8'},
    {'reference':'perl-Test-1.30-417.el8_3', 'release':'8'},
    {'reference':'perl-tests-5.26.3-417.el8_3', 'cpu':'aarch64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-tests-5.26.3-417.el8_3', 'cpu':'x86_64', 'release':'8', 'epoch':'4'},
    {'reference':'perl-Time-Piece-1.31-417.el8_3', 'cpu':'aarch64', 'release':'8'},
    {'reference':'perl-Time-Piece-1.31-417.el8_3', 'cpu':'x86_64', 'release':'8'},
    {'reference':'perl-utils-5.26.3-417.el8_3', 'release':'8'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Attribute-Handlers / perl-Devel-Peek / etc');
}