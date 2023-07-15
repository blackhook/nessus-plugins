#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4316.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120977);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2015-7837",
    "CVE-2016-3841",
    "CVE-2017-14051",
    "CVE-2017-17450",
    "CVE-2017-18079",
    "CVE-2018-1092",
    "CVE-2018-5848",
    "CVE-2018-7995",
    "CVE-2018-9516",
    "CVE-2018-1000004"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2019-4316)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2019-4316 advisory.    - The Linux kernel, as used in Red Hat Enterprise Linux 7, kernel-rt, and Enterprise MRG
2 and when booted     with UEFI Secure Boot enabled, allows local users to bypass intended securelevel/secureboot
restrictions     by leveraging improper handling of secure_boot flag across kexec reboot. (CVE-2015-7837)    - The IPv6
stack in the Linux kernel before 4.3.3 mishandles options data, which allows local users to gain     privileges or cause
a denial of service (use-after-free and system crash) via a crafted sendmsg system     call. (CVE-2016-3841)    - The
tcpmss_mangle_packet function in net/netfilter/xt_TCPMSS.c in the Linux kernel before 4.11, and 4.9.x     before 4.9.36,
allows remote attackers to cause a denial of service (use-after-free and memory corruption)     or possibly have
unspecified other impact by leveraging the presence of xt_TCPMSS in an iptables action.     (CVE-2017-18017)    - In the
Linux kernel 4.12, 3.10, 2.6 and possibly earlier versions a race condition vulnerability exists in     the sound
system, this can lead to a deadlock and denial of service condition. (CVE-2018-1000004)    - The Salsa20 encryption
algorithm in the Linux kernel before 4.14.8 does not correctly handle zero-length     inputs, allowing a local attacker
able to use the AF_ALG-based skcipher interface     (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of service
(uninitialized-memory free and kernel     crash) or have unspecified other impact by executing a crafted sequence of
system calls that use the     blkcipher_walk API. Both the generic implementation (crypto/salsa20_generic.c) and x86
implementation     (arch/x86/crypto/salsa20_glue.c) of Salsa20 were vulnerable. (CVE-2017-17805)    - The ext4_iget
function in fs/ext4/inode.c in the Linux kernel through 4.15.15 mishandles the case of a     root directory with a zero
i_links_count, which allows attackers to cause a denial of service     (ext4_process_freed_data NULL pointer dereference
and OOPS) via a crafted ext4 image. (CVE-2018-1092)    - In the function wmi_set_ie(), the length validation code does
not handle unsigned integer overflow     properly. As a result, a large value of the 'ie_len' argument can cause a
buffer overflow in all Android     releases from CAF (Android for MSM, Firefox OS for MSM, QRD Android) using the Linux
Kernel.     (CVE-2018-5848)    - Memory leak in the sas_smp_get_phy_events function in
drivers/scsi/libsas/sas_expander.c in the Linux     kernel through 4.15.7 allows local users to cause a denial of
service (memory consumption) via many read     accesses to files in the /sys/class/sas_phy directory, as demonstrated by
the     /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file. (CVE-2018-7757)    - It was found that the raw midi
kernel driver does not protect against concurrent access which leads to a     double realloc (double free) in
snd_rawmidi_input_params() and snd_rawmidi_output_status() which are part     of snd_rawmidi_ioctl() handler in
rawmidi.c file. A malicious local attacker could possibly use this for     privilege escalation. (CVE-2018-10902)    -
An elevation of privilege vulnerability in the kernel scsi driver. Product: Android. Versions: Android     kernel.
Android ID A-65023233. (CVE-2017-13168)    - ** DISPUTED ** Linux Kernel version 3.18 to 4.16 incorrectly handles an
SG_IO ioctl on /dev/sg0 with     dxfer_direction=SG_DXFER_FROM_DEV and an empty 6-byte cmdp. This may lead to copying up
to 1000 kernel     heap pages to the userspace. This has been fixed upstream in     http://www.nessus.org/u?5d4e77b1
already. The problem has     limited scope, as users don't usually have permissions to access SCSI devices. On the other
hand, e.g. the     Nero user manual suggests doing `chmod o+r+w /dev/sg*` to make the devices accessible. NOTE: third
parties     dispute the relevance of this report, noting that the requirement for an attacker to have both the
CAP_SYS_ADMIN and CAP_SYS_RAWIO capabilities makes it virtually impossible to exploit.     (CVE-2018-1000204)    - An
issue was discovered in the Linux kernel through 4.19. An information leak in cdrom_ioctl_select_disc     in
drivers/cdrom/cdrom.c could be used by local attackers to read kernel memory because a cast from     unsigned long to
int interferes with bounds checking. This is similar to CVE-2018-10940 and     CVE-2018-16658. (CVE-2018-18710)    - The
UDF filesystem implementation in the Linux kernel before 3.18.2 does not validate certain lengths,     which allows
local users to cause a denial of service (buffer over-read and system crash) via a crafted     filesystem image, related
to fs/udf/inode.c and fs/udf/symlink.c. (CVE-2014-9728)    - The msr_mtrr_valid function in arch/x86/kvm/mtrr.c in the
Linux kernel before 4.6.1 supports MSR 0x2f8,     which allows guest OS users to read or write to the kvm_arch_vcpu data
structure, and consequently obtain     sensitive information or cause a denial of service (system crash), via a crafted
ioctl call.     (CVE-2016-3713)    - The HMAC implementation (crypto/hmac.c) in the Linux kernel before 4.14.8 does not
validate that the     underlying cryptographic hash algorithm is unkeyed, allowing a local attacker able to use the
AF_ALG-based     hash interface (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3 hash algorithm (CONFIG_CRYPTO_SHA3) to cause
a     kernel stack buffer overflow by executing a crafted sequence of system calls that encounter a missing     SHA-3
initialization. (CVE-2017-17806)    - An issue was discovered in the fd_locked_ioctl function in drivers/block/floppy.c
in the Linux kernel     through 4.15.7. The floppy driver will copy a kernel pointer to user memory in response to the
FDGETPRM     ioctl. An attacker can send the FDGETPRM ioctl and use the obtained kernel pointer to discover the
location of kernel code and data and bypass kernel security protections such as KASLR. (CVE-2018-7755)    - ** DISPUTED
** drivers/scsi/libsas/sas_scsi_host.c in the Linux kernel before 4.16 allows local users to     cause a denial of
service (ata qc leak) by triggering certain failure conditions. NOTE: a third party     disputes the relevance of this
report because the failure can only occur for physically proximate     attackers who unplug SAS Host Bus Adapter cables.
(CVE-2018-10021)    - drivers/input/serio/i8042.c in the Linux kernel before 4.12.4 allows attackers to cause a denial
of     service (NULL pointer dereference and system crash) or possibly have unspecified other impact because the
port->exists value can change after it is validated. (CVE-2017-18079)    - An integer overflow in the
qla2x00_sysfs_write_optrom_ctl function in drivers/scsi/qla2xxx/qla_attr.c in     the Linux kernel through 4.12.10
allows local users to cause a denial of service (memory corruption and     system crash) by leveraging root access.
(CVE-2017-14051)    - net/netfilter/xt_osf.c in the Linux kernel through 4.14.4 does not require the CAP_NET_ADMIN
capability     for add_callback and remove_callback operations, which allows local users to bypass intended access
restrictions because the xt_osf_fingers data structure is shared across all net namespaces.     (CVE-2017-17450)    - **
DISPUTED ** Race condition in the store_int_with_restart() function in arch/x86/kernel/cpu/mcheck/mce.c     in the Linux
kernel through 4.15.7 allows local users to cause a denial of service (panic) by leveraging     root access to write to
the check_interval file in a /sys/devices/system/machinecheck/machinecheck directory. NOTE: a third party has indicated
that this report is not security relevant.     (CVE-2018-7995)    - In hid_debug_events_read of drivers/hid/hid-debug.c,
there is a possible out of bounds write due to a     missing bounds check. This could lead to local escalation of
privilege with System execution privileges     needed. User interaction is not needed for exploitation. Product: Android
Versions: Android kernel Android     ID: A-71361580. (CVE-2018-9516)  Note that Nessus has not tested for this issue but
has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-4316.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.29.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.29.1.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.8.13-118.29.1.el6uek', '3.8.13-118.29.1.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2019-4316');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.8';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-3.8.13-118.29.1.el6uek-0.4.5-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.29.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.29.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.29.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.29.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.29.1.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.29.1.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-118.29.1.el7uek-0.4.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.29.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.29.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.29.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.29.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.29.1.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.29.1.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
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
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-118.29.1.el6uek / dtrace-modules-3.8.13-118.29.1.el7uek / kernel-uek / etc');
}
