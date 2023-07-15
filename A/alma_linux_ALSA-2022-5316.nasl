##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:5316.
##

include('compat.inc');

if (description)
{
  script_id(163346);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2020-28915", "CVE-2022-27666");
  script_xref(name:"ALSA", value:"2022:5316");

  script_name(english:"AlmaLinux 8 : kernel (5316) (ALSA-2022:5316)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:5316 advisory.

  - A buffer over-read (at the framebuffer layer) in the fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka CID-6735b4632def. (CVE-2020-28915)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-5316.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28915");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27666");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

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

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-28915', 'CVE-2022-27666');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2022:5316');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-4.18.0-372.13.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-372.13.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-372.13.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
