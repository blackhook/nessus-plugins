##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10032-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162551);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_name(english:"openSUSE 15 Security Update : various openSUSE kernel module packages (openSUSE-SU-2022:10032-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:10032-1 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198581");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZLDS3QDKWQLQJITQ24HAOX6VKUI6ZXZB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2aac6f28");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtw89-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtw89-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtw89-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtw89-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtw89-ueficert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-autoload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'bbswitch-0.8-lp153.3.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bbswitch-kmp-default-0.8_k5.3.18_150300.59.76-lp153.3.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bbswitch-kmp-preempt-0.8_k5.3.18_150300.59.76-lp153.3.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mhvtl-1.62-lp153.3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mhvtl-kmp-64kb-1.62_k5.3.18_150300.59.76-lp153.3.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mhvtl-kmp-default-1.62_k5.3.18_150300.59.76-lp153.3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mhvtl-kmp-preempt-1.62_k5.3.18_150300.59.76-lp153.3.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mhvtl-kmp-preempt-1.62_k5.3.18_150300.59.76-lp153.3.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-authlibs-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-authlibs-devel-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-client-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-devel-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-fuse_client-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kernel-source-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kmp-64kb-1.8.7_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kmp-default-1.8.7_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kmp-default-1.8.7_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kmp-default-1.8.7_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kmp-preempt-1.8.7_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-kmp-preempt-1.8.7_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openafs-server-1.8.7-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-0.44-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-0.44-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-kmp-64kb-0.44_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-kmp-default-0.44_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-kmp-default-0.44_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-kmp-preempt-0.44_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcfclock-kmp-preempt-0.44_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-5.9.3.2+git20210427.6ef5d8f-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-5.9.3.2+git20210427.6ef5d8f-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-kmp-64kb-5.9.3.2+git20210427.6ef5d8f_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-kmp-default-5.9.3.2+git20210427.6ef5d8f_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-kmp-default-5.9.3.2+git20210427.6ef5d8f_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-kmp-preempt-5.9.3.2+git20210427.6ef5d8f_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtl8812au-kmp-preempt-5.9.3.2+git20210427.6ef5d8f_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-firmware-5.16~3.g38316db-lp153.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-firmware-5.16~3.g38316db-lp153.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-kmp-64kb-5.16~3.g38316db_k5.3.18_150300.59.76-lp153.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-kmp-default-5.16~3.g38316db_k5.3.18_150300.59.76-lp153.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-kmp-default-5.16~3.g38316db_k5.3.18_150300.59.76-lp153.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-kmp-preempt-5.16~3.g38316db_k5.3.18_150300.59.76-lp153.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-kmp-preempt-5.16~3.g38316db_k5.3.18_150300.59.76-lp153.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-ueficert-5.16~3.g38316db-lp153.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtw89-ueficert-5.16~3.g38316db-lp153.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-autoload-0.12.5-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-kmp-64kb-0.12.5_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-kmp-default-0.12.5_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-kmp-default-0.12.5_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-kmp-preempt-0.12.5_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-kmp-preempt-0.12.5_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v4l2loopback-utils-0.12.5-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vhba-kmp-64kb-20200106_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vhba-kmp-default-20200106_k5.3.18_150300.59.76-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vhba-kmp-preempt-20200106_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vhba-kmp-preempt-20200106_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xtables-addons-3.18-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xtables-addons-kmp-64kb-3.18_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xtables-addons-kmp-default-3.18_k5.3.18_150300.59.76-lp153.2.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xtables-addons-kmp-preempt-3.18_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xtables-addons-kmp-preempt-3.18_k5.3.18_150300.59.76-lp153.2.2.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bbswitch / bbswitch-kmp-default / bbswitch-kmp-preempt / mhvtl / etc');
}
