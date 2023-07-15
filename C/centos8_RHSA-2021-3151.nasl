#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:3151. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153151);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/10");

  script_cve_id("CVE-2021-3621");
  script_xref(name:"RHSA", value:"2021:3151");

  script_name(english:"CentOS 8 : sssd (CESA-2021:3151)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2021:3151 advisory.

  - sssd: shell command injection in sssctl (CVE-2021-3621)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3151");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-nfs-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-winbind-idmap");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sssdconfig-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sssdconfig-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-nfs-idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-nfs-idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa_hbac / libsss_autofs / libsss_certmap / libsss_idmap / etc');
}
