#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:1470.
##

include('compat.inc');

if (description)
{
  script_id(173436);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id("CVE-2022-4269", "CVE-2022-4744", "CVE-2023-0266");
  script_xref(name:"ALSA", value:"2023:1470");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"AlmaLinux 9 : kernel (ALSA-2023:1470)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:1470 advisory.

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action mirred) a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel.
    SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result
    in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit
    56b88b50565cd8b946a2d00b0c83927b7ebb055e (CVE-2023-0266)

  - kernel: tun: avoid double free in tun_free_netdev (CVE-2022-4744)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-1470.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0266");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(416, 460, 824, 833);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-4269', 'CVE-2022-4744', 'CVE-2023-0266');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2023:1470');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-5.14.0-162.22.2.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-core-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-core-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-matched-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-matched-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-extra-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-extra-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-162.22.2.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-162.22.2.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
