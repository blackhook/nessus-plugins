#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-3083.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118770);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id(
    "CVE-2015-8830",
    "CVE-2016-4913",
    "CVE-2017-0861",
    "CVE-2017-10661",
    "CVE-2017-17805",
    "CVE-2017-18208",
    "CVE-2017-18232",
    "CVE-2017-18344",
    "CVE-2017-18360",
    "CVE-2018-1092",
    "CVE-2018-1094",
    "CVE-2018-1118",
    "CVE-2018-1120",
    "CVE-2018-1130",
    "CVE-2018-5344",
    "CVE-2018-5391",
    "CVE-2018-5803",
    "CVE-2018-5848",
    "CVE-2018-7740",
    "CVE-2018-7757",
    "CVE-2018-8781",
    "CVE-2018-10322",
    "CVE-2018-10878",
    "CVE-2018-10879",
    "CVE-2018-10881",
    "CVE-2018-10883",
    "CVE-2018-10902",
    "CVE-2018-10940",
    "CVE-2018-13405",
    "CVE-2018-18690",
    "CVE-2018-1000026"
  );
  script_xref(name:"RHSA", value:"2018:3083");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2018-3083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-3083 advisory.

  - The get_rock_ridge_filename function in fs/isofs/rock.c in the Linux kernel before 4.5.5 mishandles NM
    (aka alternate name) entries containing \0 characters, which allows local users to obtain sensitive
    information from kernel memory or possibly have unspecified other impact via a crafted isofs filesystem.
    (CVE-2016-4913)

  - Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or
    cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations
    that leverage improper might_cancel queueing. (CVE-2017-10661)

  - Use-after-free vulnerability in the snd_pcm_info function in the ALSA subsystem in the Linux kernel allows
    attackers to gain privileges via unspecified vectors. (CVE-2017-0861)

  - Integer overflow in the aio_setup_single_vector function in fs/aio.c in the Linux kernel 4.0 allows local
    users to cause a denial of service or possibly have unspecified other impact via a large AIO iovec. NOTE:
    this vulnerability exists because of a CVE-2012-6701 regression. (CVE-2015-8830)

  - In the Linux Kernel before version 4.15.8, 4.14.25, 4.9.87, 4.4.121, 4.1.51, and 3.2.102, an error in the
    _sctp_make_chunk() function (net/sctp/sm_make_chunk.c) when handling SCTP packets length can be
    exploited to cause a kernel crash. (CVE-2018-5803)

  - Linux kernel before version 4.16-rc7 is vulnerable to a null pointer dereference in dccp_write_xmit()
    function in net/dccp/output.c in that allows a local user to cause a denial of service by a number of
    certain crafted system calls. (CVE-2018-1130)

  - The udl_fb_mmap function in drivers/gpu/drm/udl/udl_fb.c at the Linux kernel version 3.4 and up to and
    including 4.15 has an integer-overflow vulnerability allowing local users with access to the udldrmfb
    driver to obtain full read and write permissions on kernel physical pages, resulting in a code execution
    in kernel space. (CVE-2018-8781)

  - The timer_create syscall implementation in kernel/time/posix-timers.c in the Linux kernel before 4.14.8
    doesn't properly validate the sigevent->sigev_notify field, which leads to out-of-bounds access in the
    show_timer function (called when /proc/$PID/timers is read). This allows userspace applications to read
    arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE).
    (CVE-2017-18344)

  - The Linux kernel, versions 3.9+, is vulnerable to a denial of service attack with low rates of specially
    modified packets targeting IP fragment re-assembly. An attacker may cause a denial of service condition by
    sending specially crafted IP fragments. Various vulnerabilities in IP fragmentation have been discovered
    and fixed over the years. The current vulnerability (CVE-2018-5391) became exploitable in the Linux kernel
    with the increase of the IP fragment reassembly queue size. (CVE-2018-5391)

  - The inode_init_owner function in fs/inode.c in the Linux kernel through 3.16 allows local users to create
    files with an unintended group ownership, in a scenario where a directory is SGID to a certain group and
    is writable by a user who is not a member of that group. Here, the non-member can trigger creation of a
    plain file whose group ownership is that group. The intended behavior was that the non-member can trigger
    creation of a directory (but not a plain file) whose group ownership is that group. The non-member can
    escalate privileges by making the plain file executable and SGID. (CVE-2018-13405)

  - The Salsa20 encryption algorithm in the Linux kernel before 4.14.8 does not correctly handle zero-length
    inputs, allowing a local attacker able to use the AF_ALG-based skcipher interface
    (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of service (uninitialized-memory free and kernel
    crash) or have unspecified other impact by executing a crafted sequence of system calls that use the
    blkcipher_walk API. Both the generic implementation (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 were vulnerable. (CVE-2017-17805)

  - The madvise_willneed function in mm/madvise.c in the Linux kernel before 4.14.4 allows local users to
    cause a denial of service (infinite loop) by triggering use of MADVISE_WILLNEED for a DAX mapping.
    (CVE-2017-18208)

  - The Serial Attached SCSI (SAS) implementation in the Linux kernel through 4.15.9 mishandles a mutex within
    libsas, which allows local users to cause a denial of service (deadlock) by triggering certain error-
    handling code. (CVE-2017-18232)

  - The ext4_iget function in fs/ext4/inode.c in the Linux kernel through 4.15.15 mishandles the case of a
    root directory with a zero i_links_count, which allows attackers to cause a denial of service
    (ext4_process_freed_data NULL pointer dereference and OOPS) via a crafted ext4 image. (CVE-2018-1092)

  - In the function wmi_set_ie(), the length validation code does not handle unsigned integer overflow
    properly. As a result, a large value of the 'ie_len' argument can cause a buffer overflow in all Android
    releases from CAF (Android for MSM, Firefox OS for MSM, QRD Android) using the Linux Kernel.
    (CVE-2018-5848)

  - Memory leak in the sas_smp_get_phy_events function in drivers/scsi/libsas/sas_expander.c in the Linux
    kernel through 4.15.7 allows local users to cause a denial of service (memory consumption) via many read
    accesses to files in the /sys/class/sas_phy directory, as demonstrated by the
    /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file. (CVE-2018-7757)

  - The xfs_dinode_verify function in fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel through 4.16.3 allows
    local users to cause a denial of service (xfs_ilock_attr_map_shared invalid pointer dereference) via a
    crafted xfs image. (CVE-2018-10322)

  - A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bounds write and
    a denial of service or unspecified other impact is possible by mounting and operating a crafted ext4
    filesystem image. (CVE-2018-10878)

  - The ext4_fill_super function in fs/ext4/super.c in the Linux kernel through 4.15.15 does not always
    initialize the crc32c checksum driver, which allows attackers to cause a denial of service
    (ext4_xattr_inode_hash NULL pointer dereference and system crash) via a crafted ext4 image.
    (CVE-2018-1094)

  - Linux kernel vhost since version 4.8 does not properly initialize memory in messages passed between
    virtual guests and the host operating system in the vhost/vhost.c:vhost_new_msg() function. This can allow
    local privileged users to read some kernel memory contents when reading from the /dev/vhost-net device
    file. (CVE-2018-1118)

  - A flaw was found affecting the Linux kernel before version 4.17. By mmap()ing a FUSE-backed file onto a
    process's memory containing command line arguments (or environment strings), an attacker can cause
    utilities from psutils or procps (such as ps, w) or any other program which makes a read() call to the
    /proc//cmdline (or /proc//environ) files to block indefinitely (denial of service) or for some
    controlled time (as a synchronization primitive for other attacks). (CVE-2018-1120)

  - In the Linux kernel through 4.14.13, drivers/block/loop.c mishandles lo_release serialization, which
    allows attackers to cause a denial of service (__lock_acquire use-after-free) or possibly have unspecified
    other impact. (CVE-2018-5344)

  - The resv_map_release function in mm/hugetlb.c in the Linux kernel through 4.15.7 allows local users to
    cause a denial of service (BUG) via a crafted application that makes mmap system calls and has a large
    pgoff argument to the remap_file_pages system call. (CVE-2018-7740)

  - A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause a use-after-free in
    ext4_xattr_set_entry function and a denial of service or unspecified other impact may occur by renaming a
    file in a crafted ext4 filesystem image. (CVE-2018-10879)

  - A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and a system crash by mounting and operating on a
    crafted ext4 filesystem image. (CVE-2018-10881)

  - A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bounds write in
    jbd2_journal_dirty_metadata(), a denial of service, and a system crash by mounting and operating on a
    crafted ext4 filesystem image. (CVE-2018-10883)

  - It was found that the raw midi kernel driver does not protect against concurrent access which leads to a
    double realloc (double free) in snd_rawmidi_input_params() and snd_rawmidi_output_status() which are part
    of snd_rawmidi_ioctl() handler in rawmidi.c file. A malicious local attacker could possibly use this for
    privilege escalation. (CVE-2018-10902)

  - The cdrom_ioctl_media_changed function in drivers/cdrom/cdrom.c in the Linux kernel before 4.16.6 allows
    local attackers to use a incorrect bounds check in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read out
    kernel memory. (CVE-2018-10940)

  - Linux Linux kernel version at least v4.8 onwards, probably well before contains a Insufficient input
    validation vulnerability in bnx2x network card driver that can result in DoS: Network card firmware
    assertion takes card off-line. This attack appear to be exploitable via An attacker on a must pass a very
    large, specially crafted packet to the bnx2x card. This can be done from an untrusted guest VM..
    (CVE-2018-1000026)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-3083.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10661");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8781");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.10.0-957.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-3083');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-957.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-957.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
