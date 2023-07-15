##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:4670. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145873);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-10735",
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2018-20676",
    "CVE-2018-20677",
    "CVE-2019-8331",
    "CVE-2019-11358",
    "CVE-2020-1722",
    "CVE-2020-11022"
  );
  script_bugtraq_id(105658, 107375, 108023);
  script_xref(name:"RHSA", value:"2020:4670");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 8 : idm:DL1 and idm:client (CESA-2020:4670)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4670 advisory.

  - jquery: Cross-site scripting via cross-domain ajax requests (CVE-2015-9251)

  - bootstrap: XSS in the data-target attribute (CVE-2016-10735)

  - bootstrap: Cross-site Scripting (XSS) in the collapse data-parent attribute (CVE-2018-14040)

  - bootstrap: Cross-site Scripting (XSS) in the data-container property of tooltip (CVE-2018-14042)

  - bootstrap: XSS in the tooltip data-viewport attribute (CVE-2018-20676)

  - bootstrap: XSS in the affix configuration target property (CVE-2018-20677)

  - jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution, or
    property injection (CVE-2019-11358)

  - bootstrap: XSS in the tooltip or popover data-template attribute (CVE-2019-8331)

  - jquery: Cross-site scripting due to improper injQuery.htmlPrefilter method (CVE-2020-11022)

  - ipa: No password length restriction leads to denial of service (CVE-2020-1722)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4670");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-healthcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-healthcheck-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:softhsm-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/idm');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:client');
if ('client' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module idm:' + module_ver);

var appstreams = {
    'idm:client': [
      {'reference':'bind-dyndb-ldap-11.3-1.module_el8.3.0+482+9e103aab', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bind-dyndb-ldap-11.3-1.module_el8.3.0+482+9e103aab', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module_el8.1.0+253+3b90c921', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module_el8.1.0+253+3b90c921', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.4-6.module_el8.3.0+482+9e103aab', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.4-6.module_el8.3.0+482+9e103aab', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.4-6.module_el8.3.0+481+b9a999c3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.4-6.module_el8.3.0+481+b9a999c3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.6-2.module_el8.3.0+482+9e103aab', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.6-2.module_el8.3.0+482+9e103aab', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module_el8.1.0+253+3b90c921', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module_el8.1.0+253+3b90c921', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.8.7-12.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module_el8.1.0+265+e1e65be4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module_el8.1.0+265+e1e65be4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module_el8.2.0+374+0d2d74a1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module_el8.2.0+374+0d2d74a1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module_el8.1.0+265+e1e65be4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module_el8.1.0+265+e1e65be4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module_el8.1.0+265+e1e65be4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module_el8.1.0+265+e1e65be4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module_el8.1.0+265+e1e65be4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module_el8.1.0+265+e1e65be4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module_el8.1.0+253+3b90c921', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module_el8.1.0+253+3b90c921', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.5-4.module_el8.3.0+511+8a502f20', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.5-4.module_el8.3.0+511+8a502f20', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-3.module_el8.3.0+482+9e103aab', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-3.module_el8.3.0+482+9e103aab', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-3.module_el8.3.0+482+9e103aab', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-3.module_el8.3.0+482+9e103aab', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:client');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / custodia / ipa-client / ipa-client-common / etc');
}
