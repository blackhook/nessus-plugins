#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110694);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2012-6701",
    "CVE-2015-8830",
    "CVE-2016-8650",
    "CVE-2017-12190",
    "CVE-2017-18203",
    "CVE-2017-2671",
    "CVE-2017-6001",
    "CVE-2017-7616",
    "CVE-2017-7889",
    "CVE-2018-10675",
    "CVE-2018-5803",
    "CVE-2018-7757"
  );

  script_name(english:"Virtuozzo 6 : parallels-server-bm-release / vzkernel / etc (VZA-2018-041)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the parallels-server-bm-release /
vzkernel / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - The do_get_mempolicy() function in 'mm/mempolicy.c' in
    the Linux kernel allows local users to hit a
    use-after-free bug via crafted system calls and thus
    cause a denial of service (DoS) or possibly have
    unspecified other impact. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out.

  - It was found that AIO interface didn't use the proper
    rw_verify_area() helper function with extended
    functionality, for example, mandatory locking on the
    file. Also rw_verify_area() makes extended checks, for
    example, that the size of the access doesn't cause
    overflow of the provided offset limits. This integer
    overflow in fs/aio.c in the Linux kernel before 3.4.1
    allows local users to cause a denial of service or
    possibly have unspecified other impact via a large AIO
    iovec.

  - Integer overflow in the aio_setup_single_vector
    function in fs/aio.c in the Linux kernel 4.0 allows
    local users to cause a denial of service or possibly
    have unspecified other impact via a large AIO iovec.
    NOTE: this vulnerability exists because of a
    CVE-2012-6701 regression.

  - A flaw was found in the Linux kernel key management
    subsystem in which a local attacker could crash the
    kernel or corrupt the stack and additional memory
    (denial of service) by supplying a specially crafted
    RSA key. This flaw panics the machine during the
    verification of the RSA key.

  - A race condition leading to a NULL pointer dereference
    was found in the Linux kernel's Link Layer Control
    implementation. A local attacker with access to ping
    sockets could use this flaw to crash the system.

  - It was found that the original fix for CVE-2016-6786
    was incomplete. There exist a race between two
    concurrent sys_perf_event_open() calls when both try
    and move the same pre-existing software group into a
    hardware context.

  - Incorrect error handling in the set_mempolicy() and
    mbind() compat syscalls in 'mm/mempolicy.c' in the
    Linux kernel allows local users to obtain sensitive
    information from uninitialized stack data by triggering
    failure of a certain bitmap operation.

  - The mm subsystem in the Linux kernel through 4.10.10
    does not properly enforce the CONFIG_STRICT_DEVMEM
    protection mechanism, which allows local users to read
    or write to kernel memory locations in the first
    megabyte (and bypass slab-allocation access
    restrictions) via an application that opens the
    /dev/mem file, related to arch/x86/mm/init.c and
    drivers/char/mem.c.

  - It was found that in the Linux kernel through
    v4.14-rc5, bio_map_user_iov() and bio_unmap_user() in
    'block/bio.c' do unbalanced pages refcounting if IO
    vector has small consecutive buffers belonging to the
    same page. bio_add_pc_page() merges them into one, but
    the page reference is never dropped, causing a memory
    leak and possible system lockup due to out-of-memory
    condition.

  - The Linux kernel, before version 4.14.3, is vulnerable
    to a denial of service in
    drivers/md/dm.c:dm_get_from_kobject() which can be
    caused by local users leveraging a race condition with
    __dm_destroy() during creation and removal of DM
    devices. Only privileged local users (with
    CAP_SYS_ADMIN capability) can directly perform the
    ioctl operations for dm device creation and removal and
    this would typically be outside the direct control of
    the unprivileged attacker.

  - An error in the '_sctp_make_chunk()' function
    (net/sctp/sm_make_chunk.c) when handling SCTP, packet
    length can be exploited by a malicious local user to
    cause a kernel crash and a DoS.

  - Memory leak in the sas_smp_get_phy_events function in
    drivers/scsi/libsas/sas_expander.c in the Linux kernel
    allows local users to cause a denial of service (kernel
    memory exhaustion) via multiple read accesses to files
    in the /sys/class/sas_phy directory.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2945474");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1854");
  script_set_attribute(attribute:"solution", value:
"Update the affected parallels-server-bm-release / vzkernel / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["parallels-server-bm-release-6.0.12-3709",
        "vzkernel-2.6.32-042stab131.1",
        "vzkernel-devel-2.6.32-042stab131.1",
        "vzkernel-firmware-2.6.32-042stab131.1",
        "vzmodules-2.6.32-042stab131.1",
        "vzmodules-devel-2.6.32-042stab131.1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "parallels-server-bm-release / vzkernel / etc");
}
