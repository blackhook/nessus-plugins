##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:5163.
##

include('compat.inc');

if (description)
{
  script_id(162838);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/08");

  script_cve_id("CVE-2020-13950");
  script_xref(name:"RLSA", value:"2022:5163");

  script_name(english:"Rocky Linux 8 : httpd:2.4 (RLSA-2022:5163)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:5163 advisory.

  - Apache HTTP Server versions 2.4.41 to 2.4.46 mod_proxy_http can be made to crash (NULL pointer
    dereference) with specially crafted requests using both Content-Length and Transfer-Encoding headers,
    leading to a Denial of Service (CVE-2020-13950)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:5163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966738");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:httpd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_http2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_http2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_md-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_md-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_proxy_html-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_session-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mod_ssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'httpd-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debugsource-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debugsource-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-filesystem-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-manual-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-1.15.7-5.module+el8.6.0+823+f143cee1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-1.15.7-5.module+el8.6.0+823+f143cee1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-debuginfo-1.15.7-5.module+el8.6.0+823+f143cee1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-debuginfo-1.15.7-5.module+el8.6.0+823+f143cee1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-debugsource-1.15.7-5.module+el8.6.0+823+f143cee1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_http2-debugsource-1.15.7-5.module+el8.6.0+823+f143cee1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-2.0.8-8.module+el8.5.0+695+1fa8055e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-2.0.8-8.module+el8.5.0+695+1fa8055e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-debuginfo-2.0.8-8.module+el8.5.0+695+1fa8055e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-debuginfo-2.0.8-8.module+el8.5.0+695+1fa8055e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-debugsource-2.0.8-8.module+el8.5.0+695+1fa8055e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-debugsource-2.0.8-8.module+el8.5.0+695+1fa8055e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-debuginfo-2.4.37-47.module+el8.6.0+985+b8ff6398.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-debuginfo / httpd-debugsource / httpd-devel / etc');
}
