#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:5142.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158848);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/11");

  script_cve_id("CVE-2020-25719");
  script_xref(name:"ALSA", value:"2021:5142");

  script_name(english:"AlmaLinux 8 : idm:DL1 (ALSA-2021:5142)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2021:5142 advisory.

  - A flaw was found in the way Samba, as an Active Directory Domain Controller, implemented Kerberos name-
    based authentication. The Samba AD DC, could become confused about the user a ticket represents if it did
    not strictly require a Kerberos PAC and always use the SIDs found within. The result could include total
    domain compromise. (CVE-2020-25719)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-5142.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-healthcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-healthcheck-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipatests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:softhsm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/idm');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');
if ('DL1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module idm:' + module_ver);

var appstreams = {
    'idm:DL1': [
      {'reference':'bind-dyndb-ldap-11.6-2.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.9.6-10.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.9.6-10.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.9.6-10.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.7-6.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.7-6.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.9.6-10.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.9.6-10.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.7-1.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipatests-4.9.6-10.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module_el8.5.0+2603+92118e57', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.6-4.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-5.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-5.module_el8.5.0+2603+92118e57', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / custodia / ipa-client / ipa-client-common / etc');
}
