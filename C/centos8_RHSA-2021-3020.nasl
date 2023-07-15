#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:3020. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152359);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/09");

  script_cve_id(
    "CVE-2020-36327",
    "CVE-2021-31799",
    "CVE-2021-31810",
    "CVE-2021-32066"
  );
  script_xref(name:"RHSA", value:"2021:3020");

  script_name(english:"CentOS 8 : ruby:2.7 (CESA-2021:3020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:3020 advisory.

  - rubygem-bundler: Dependencies of gems with explicit source may be installed from a different source
    (CVE-2020-36327)

  - rubygem-rdoc: Command injection vulnerability in RDoc (CVE-2021-31799)

  - ruby: FTP PASV command response can cause Net::FTP to connect to arbitrary host (CVE-2021-31810)

  - ruby: StartTLS stripping vulnerability in Net::IMAP (CVE-2021-32066)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3020");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'ruby-2.7.4-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-2.7.4-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-default-gems-2.7.4-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-default-gems-2.7.4-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-2.7.4-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-2.7.4-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-doc-2.7.4-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-doc-2.7.4-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-2.7.4-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-2.7.4-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-0.4.0-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-0.4.0-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-doc-0.4.0-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-doc-0.4.0-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-2.0.0-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-2.0.0-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-4.8.1-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-4.8.1-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-doc-4.8.1-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-doc-4.8.1-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-2.2.24-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-2.2.24-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.6-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.6-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-irb-1.2.6-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-irb-1.2.6-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.3.0-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.3.0-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-minitest-5.13.0-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-minitest-5.13.0-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-2.11.3-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-2.11.3-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-doc-2.11.3-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-doc-2.11.3-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-0.5.3-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-0.5.3-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-doc-0.5.3-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-doc-0.5.3-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-net-telnet-0.2.0-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-net-telnet-0.2.0-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-2.1.2-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-2.1.2-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-1.2.3-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-1.2.3-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-doc-1.2.3-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-doc-1.2.3-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-power_assert-1.1.7-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-power_assert-1.1.7-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.1.0-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.1.0-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rake-13.0.1-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rake-13.0.1-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rdoc-6.2.1.1-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rdoc-6.2.1.1-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-test-unit-3.3.4-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-test-unit-3.3.4-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-xmlrpc-0.3.0-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-xmlrpc-0.3.0-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-3.1.6-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-3.1.6-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-devel-3.1.6-137.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-devel-3.1.6-137.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-default-gems / ruby-devel / ruby-doc / ruby-libs / etc');
}
