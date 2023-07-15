#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:5195 and
# CentOS Errata and Security Advisory 2021:5195 respectively.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156242);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/01");

  script_cve_id("CVE-2020-25719");
  script_xref(name:"RHSA", value:"2021:5195");

  script_name(english:"CentOS 7 : ipa (CESA-2021:5195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2021:5195 advisory.

  - samba: Samba AD DC did not always rely on the SID and PAC in Kerberos tickets (CVE-2020-25719)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2021-December/060977.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1b0a255");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/287.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
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
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'ipa-client-4.6.8-5.el7.centos.10', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-python-compat-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.6.8-5.el7.centos.10', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.6.8-5.el7.centos.10', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaclient-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipalib-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-ipaserver-4.6.8-5.el7.centos.10', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipa-client / ipa-client-common / ipa-common / etc');
}
