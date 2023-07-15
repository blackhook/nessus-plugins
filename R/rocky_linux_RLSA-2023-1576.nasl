#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:1576.
##

include('compat.inc');

if (description)
{
  script_id(173980);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id("CVE-2022-2625", "CVE-2022-41862");
  script_xref(name:"RLSA", value:"2023:1576");
  script_xref(name:"IAVB", value:"2022-B-0028-S");
  script_xref(name:"IAVB", value:"2023-B-0009-S");

  script_name(english:"Rocky Linux 8 : postgresql:13 (RLSA-2023:1576)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:1576 advisory.

  - A vulnerability was found in PostgreSQL. This attack requires permission to create non-temporary objects
    in at least one schema, the ability to lure or wait for an administrator to create or update an affected
    extension in that schema, and the ability to lure or wait for a victim to use the object targeted in
    CREATE OR REPLACE or CREATE IF NOT EXISTS. Given all three prerequisites, this flaw allows an attacker to
    run arbitrary code as the victim role, which may be a superuser. (CVE-2022-2625)

  - In PostgreSQL, a modified, unauthenticated server can send an unterminated string during the establishment
    of Kerberos transport encryption. In certain conditions a server can cause a libpq client to over-read and
    report an error message containing uninitialized bytes. (CVE-2022-41862)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:1576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2113825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165722");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pg_repack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pg_repack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pg_repack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-docs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plpython3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'pg_repack-1.4.6-3.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pg_repack-1.4.6-3.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pg_repack-debuginfo-1.4.6-3.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pg_repack-debuginfo-1.4.6-3.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pg_repack-debugsource-1.4.6-3.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pg_repack-debugsource-1.4.6-3.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pgaudit-1.5.0-1.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pgaudit-1.5.0-1.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pgaudit-debuginfo-1.5.0-1.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pgaudit-debuginfo-1.5.0-1.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pgaudit-debugsource-1.5.0-1.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pgaudit-debugsource-1.5.0-1.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debuginfo-0.10.0-2.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debuginfo-0.10.0-2.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debugsource-0.10.0-2.module+el8.5.0+684+c3892ef9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debugsource-0.10.0-2.module+el8.5.0+684+c3892ef9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-contrib-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-contrib-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-contrib-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-contrib-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-debugsource-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-debugsource-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-docs-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-docs-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-docs-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-docs-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plperl-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plperl-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plperl-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plperl-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plpython3-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plpython3-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plpython3-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-plpython3-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-pltcl-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-pltcl-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-pltcl-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-pltcl-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-devel-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-devel-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-devel-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-server-devel-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-static-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-static-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-test-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-test-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-test-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-test-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-test-rpm-macros-13.10-1.module+el8.7.0+1175+026203e7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-devel-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-devel-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-devel-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-upgrade-devel-debuginfo-13.10-1.module+el8.7.0+1175+026203e7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pg_repack / pg_repack-debuginfo / pg_repack-debugsource / pgaudit / etc');
}
