#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0403 and
# CentOS Errata and Security Advisory 2023:0403 respectively.
##

include('compat.inc');

if (description)
{
  script_id(170864);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id("CVE-2022-4254");
  script_xref(name:"RHSA", value:"2023:0403");

  script_name(english:"CentOS 7 : sssd (CESA-2023:0403)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2023:0403 advisory.

  - sssd: libsss_certmap fails to sanitise certificate data used in LDAP filters (CVE-2022-4254)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2023-January/086361.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e32a9d34");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(90);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sssdconfig");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'libipa_hbac-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libipa_hbac-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libsss_nss_idmap-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-murmur-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sssdconfig-1.16.5-10.el7_9.15', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.16.5-10.el7_9.15', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-1.16.5-10.el7_9.15', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa_hbac / libipa_hbac-devel / libsss_autofs / etc');
}
