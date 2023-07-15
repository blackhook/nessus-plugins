##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3984.
##

include('compat.inc');

if (description)
{
  script_id(141233);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2019-10143", "CVE-2019-13456", "CVE-2019-17185");

  script_name(english:"Oracle Linux 7 : freeradius (ELSA-2020-3984)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-3984 advisory.

  - ** DISPUTED ** It was discovered freeradius up to and including version 3.0.19 does not correctly
    configure logrotate, allowing a local attacker who already has control of the radiusd user to escalate his
    privileges to root, by tricking logrotate into writing a radiusd-writable file to a directory normally
    inaccessible by the radiusd user. NOTE: the upstream software maintainer has stated there is simply no
    way for anyone to gain privileges through this alleged issue. (CVE-2019-10143)

  - In FreeRADIUS 3.0 through 3.0.19, on average 1 in every 2048 EAP-pwd handshakes fails because the password
    element cannot be found within 10 iterations of the hunting and pecking loop. This leaks information that
    an attacker can use to recover the password of any user. This information leakage is similar to the
    Dragonblood attack and CVE-2019-9494. (CVE-2019-13456)

  - In FreeRADIUS 3.0.x before 3.0.20, the EAP-pwd module used a global OpenSSL BN_CTX instance to handle all
    handshakes. This mean multiple threads use the same BN_CTX instance concurrently, resulting in crashes
    when concurrent EAP-pwd handshakes are initiated. This can be abused by an adversary as a Denial-of-
    Service (DoS) attack. (CVE-2019-17185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-3984.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeradius-utils");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'freeradius-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-devel-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-devel-3.0.13-15.el7', 'cpu':'i686', 'release':'7'},
    {'reference':'freeradius-devel-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-doc-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-doc-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-krb5-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-krb5-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-ldap-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-ldap-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-mysql-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-mysql-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-perl-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-perl-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-postgresql-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-postgresql-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-python-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-python-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-sqlite-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-sqlite-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-unixODBC-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-unixODBC-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'},
    {'reference':'freeradius-utils-3.0.13-15.el7', 'cpu':'aarch64', 'release':'7'},
    {'reference':'freeradius-utils-3.0.13-15.el7', 'cpu':'x86_64', 'release':'7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freeradius / freeradius-devel / freeradius-doc / etc');
}