#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:3816. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154050);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-26691", "CVE-2021-40438");
  script_xref(name:"IAVA", value:"2021-A-0259-S");
  script_xref(name:"IAVA", value:"2021-A-0440-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");
  script_xref(name:"RHSA", value:"2021:3816");

  script_name(english:"CentOS 8 : httpd:2.4 (CESA-2021:3816)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:3816 advisory.

  - httpd: mod_session: Heap overflow via a crafted SessionHeader value (CVE-2021-26691)

  - httpd: mod_proxy: SSRF via a crafted request uri-path containing unix: (CVE-2021-40438)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3816");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'httpd-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-filesystem-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-filesystem-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-manual-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-manual-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-1.15.7-3.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-1.15.7-3.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-2.0.8-8.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_md-2.0.8-8.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_proxy_html-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_proxy_html-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_session-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.37-39.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_ssl-2.4.37-39.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-filesystem / httpd-manual / httpd-tools / etc');
}
