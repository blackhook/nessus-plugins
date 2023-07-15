#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:5263.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167691);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/17");

  script_cve_id("CVE-2022-26353", "CVE-2022-26354");
  script_xref(name:"ALSA", value:"2022:5263");

  script_name(english:"AlmaLinux 9 : qemu-kvm (ALSA-2022:5263)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:5263 advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-5263.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(401, 416, 772);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-gpu-ccw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-gpu-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-gpu-pci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-gpu-pci-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-display-virtio-vga-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-usb-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-device-usb-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-ui-egl-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-pr-helper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

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

var pkgs = [
    {'reference':'qemu-guest-agent-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-guest-agent-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-img-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-img-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-audio-pa-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-audio-pa-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-block-curl-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-block-curl-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-block-rbd-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-block-rbd-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-common-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-common-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-core-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-core-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-ccw-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-ccw-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-gl-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-gl-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-pci-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-pci-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-pci-gl-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-gpu-pci-gl-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-vga-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-vga-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-vga-gl-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-display-virtio-vga-gl-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-usb-host-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-usb-host-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-usb-redirect-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-device-usb-redirect-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-docs-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-docs-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-tools-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-tools-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-ui-egl-headless-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-ui-egl-headless-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-ui-opengl-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-kvm-ui-opengl-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-pr-helper-6.2.0-11.el9_0.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
    {'reference':'qemu-pr-helper-6.2.0-11.el9_0.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-audio-pa / etc');
}
