#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:3147.
##

include('compat.inc');

if (description)
{
  script_id(177619);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_cve_id("CVE-2022-25147");
  script_xref(name:"RLSA", value:"2023:3147");

  script_name(english:"Rocky Linux 9 : apr-util (RLSA-2023:3147)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2023:3147 advisory.

  - Integer Overflow or Wraparound vulnerability in apr_base64 functions of Apache Portable Runtime Utility
    (APR-util) allows an attacker to write beyond bounds of a buffer. This issue affects Apache Portable
    Runtime Utility (APR-util) 1.6.1 and prior versions. (CVE-2022-25147)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:3147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2169652");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-bdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-bdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apr-util-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'apr-util-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-1.6.1-20.el9_2.1', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-1.6.1-20.el9_2.1', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-bdb-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-debugsource-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-debugsource-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-debugsource-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-devel-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-devel-1.6.1-20.el9_2.1', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-devel-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-devel-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-ldap-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-ldap-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-ldap-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-ldap-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-ldap-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-ldap-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-mysql-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-mysql-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-mysql-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-mysql-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-mysql-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-mysql-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-odbc-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-odbc-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-odbc-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-odbc-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-odbc-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-odbc-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-openssl-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-openssl-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-openssl-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-openssl-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-openssl-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-openssl-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-pgsql-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-pgsql-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-pgsql-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-pgsql-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-pgsql-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-pgsql-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-sqlite-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-sqlite-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-sqlite-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-sqlite-debuginfo-1.6.1-20.el9_2.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-sqlite-debuginfo-1.6.1-20.el9_2.1', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apr-util-sqlite-debuginfo-1.6.1-20.el9_2.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apr-util / apr-util-bdb / apr-util-bdb-debuginfo / etc');
}
