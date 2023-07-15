##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3984 and
# CentOS Errata and Security Advisory 2020:3984 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141587);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2019-10143", "CVE-2019-13456", "CVE-2019-17185");
  script_xref(name:"RHSA", value:"2020:3984");

  script_name(english:"CentOS 7 : freeradius (CESA-2020:3984)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:3984 advisory.

  - freeradius: privilege escalation due to insecure logrotate configuration (CVE-2019-10143)

  - freeradius: eap-pwd: Information leak due to aborting when needing more than 10 iterations
    (CVE-2019-13456)

  - freeradius: eap-pwd: DoS issues due to multithreaded BN_CTX access (CVE-2019-17185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012702.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51aa1007");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/250.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/266.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/567.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 250, 266, 567);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'freeradius-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-devel-3.0.13-15.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'freeradius-devel-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-doc-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-krb5-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-ldap-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-mysql-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-perl-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-postgresql-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-python-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-sqlite-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-unixODBC-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freeradius-utils-3.0.13-15.el7', 'cpu':'x86_64', 'release':'CentOS-7'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
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

if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freeradius / freeradius-devel / freeradius-doc / etc');
}
