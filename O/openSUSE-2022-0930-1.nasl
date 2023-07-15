#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0930-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159180);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-3930", "CVE-2022-0358");

  script_name(english:"openSUSE 15 Security Update : qemu (openSUSE-SU-2022:0930-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0930-1 advisory.

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - QEMU: virtiofsd: potential privilege escalation via CVE-2018-13405 (CVE-2022-0358)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196737");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VFLDWSRMX7BN3NXC6GXAFPJLCC5D5KIJ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3db76346");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0358");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3930");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-SLOF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-chardev-baum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-chardev-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-display-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-display-virtio-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-display-virtio-gpu-pci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-display-virtio-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-s390x-virtio-gpu-ccw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-usb-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-hw-usb-smartcard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-skiboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-spice-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-spice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vhost-user-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
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
    {'reference':'qemu-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-SLOF-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-arm-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-spice-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-gluster-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-chardev-baum-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-chardev-spice-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-extra-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-display-qxl-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-display-virtio-gpu-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-display-virtio-gpu-pci-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-display-virtio-vga-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-s390x-virtio-gpu-ccw-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-usb-redirect-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-hw-usb-smartcard-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ipxe-1.0.0+-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ivshmem-tools-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ksm-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-5.2.0-150300.112.4', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-5.2.0-150300.112.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-lang-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-linux-user-5.2.0-150300.112.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-microvm-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ppc-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-s390x-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-seabios-1.14.0_0_g155821a-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-sgabios-8-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-skiboot-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-testsuite-5.2.0-150300.112.7', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-tools-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-opengl-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-spice-app-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-spice-core-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-vgabios-1.14.0_0_g155821a-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-vhost-user-gpu-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-x86-5.2.0-150300.112.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-SLOF / qemu-arm / qemu-audio-alsa / qemu-audio-pa / etc');
}
