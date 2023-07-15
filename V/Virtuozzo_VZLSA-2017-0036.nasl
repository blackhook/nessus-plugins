#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101405);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-4998",
    "CVE-2016-6828",
    "CVE-2016-7117"
  );

  script_name(english:"Virtuozzo 6 : kernel / kernel-abi-whitelists / kernel-debug / etc (VZLSA-2017-0036)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A use-after-free vulnerability was found in the kernels socket
recvmmsg subsystem. This may allow remote attackers to corrupt memory
and may allow execution of arbitrary code. This corruption takes place
during the error handling routines within __sys_recvmmsg() function.
(CVE-2016-7117, Important)

* An out-of-bounds heap memory access leading to a Denial of Service,
heap disclosure, or further impact was found in setsockopt(). The
function call is normally restricted to root, however some processes
with cap_sys_admin may also be able to trigger this flaw in privileged
container environments. (CVE-2016-4998, Moderate)

* A use-after-free vulnerability was found in
tcp_xmit_retransmit_queue and other tcp_* functions. This condition
could allow an attacker to send an incorrect selective acknowledgment
to existing connections, possibly resetting a connection.
(CVE-2016-6828, Moderate)

Bug Fix(es) :

* When parallel NFS returned a file layout, a kernel crash sometimes
occurred. This update removes the call to the BUG_ON() function from a
code path of a client that returns the file layout. As a result, the
kernel no longer crashes in the described situation. (BZ#1385480)

* When a guest virtual machine (VM) on Microsoft Hyper-V was set to
crash on a Nonmaskable Interrupt (NMI) that was injected from the
host, this VM became unresponsive and did not create the vmcore dump
file. This update applies a set of patches to the Virtual Machine Bus
kernel driver (hv_vmbus) that fix this bug. As a result, the VM now
first creates and saves the vmcore dump file and then reboots.
(BZ#1385482)

* From Red Hat Enterprise Linux 6.6 to 6.8, the IPv6 routing cache
occasionally showed incorrect values. This update fixes the
DST_NOCOUNT mechanism, and the IPv6 routing cache now shows correct
values. (BZ# 1391974)

* When using the ixgbe driver and the software Fibre Channel over
Ethernet (FCoE) stack, suboptimal performance in some cases occurred
on systems with a large number of CPUs. This update fixes the
fc_exch_alloc() function to try all the available exchange managers in
the list for an available exchange ID. This change avoids failing
allocations, which previously led to the host busy status.
(BZ#1392818)

* When the vmwgfx kernel module loads, it overrides the boot
resolution automatically. Consequently, users were not able to change
the resolution by manual setting of the kernel's 'vga=' parameter in
the /boot/grub/ grub.conf file. This update adds the 'nomodeset'
parameter, which can be set in the /boot/grub/grub.conf file. The
'nomodeset' parameter allows the users to prevent the vmwgfx driver
from loading. As a result, the setting of the 'vga=' parameter works
as expected, in case that vmwgfx does not load. (BZ#1392875)

* When Red Hat Enterprise Linux 6.8 was booted on SMBIOS 3.0 based
systems, Desktop Management Interface (DMI) information, which is
referenced by several applications, such as NEC server's memory RAS
utility, was missing entries in the sysfs virtual file system. This
update fixes the underlying source code, and sysfs now shows the DMI
information as expected. (BZ# 1393464)

* Previously, bonding mode active backup and the propagation of the
media access control (MAC) address to a VLAN interface did not work in
Red Hat Enterprise Linux 6.8, when the fail_over_mac bonding parameter
was set to fail_over_mac=active. With this update, the underlying
source code has been fixed so that the VLANs continue inheriting the
MAC address of the active physical interface until the VLAN MAC
address is explicitly set to any value. As a result, IPv6 EUI64
addresses for the VLAN can reflect any changes to the MAC address of
the physical interface, and Duplicate Address Detection (DAD) behaves
as expected. (BZ#1396479)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0036.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93f0c8f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0036");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel / kernel-abi-whitelists / kernel-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-2.6.32-642.13.1.vl6",
        "kernel-abi-whitelists-2.6.32-642.13.1.vl6",
        "kernel-debug-2.6.32-642.13.1.vl6",
        "kernel-debug-devel-2.6.32-642.13.1.vl6",
        "kernel-devel-2.6.32-642.13.1.vl6",
        "kernel-doc-2.6.32-642.13.1.vl6",
        "kernel-firmware-2.6.32-642.13.1.vl6",
        "kernel-headers-2.6.32-642.13.1.vl6",
        "perf-2.6.32-642.13.1.vl6",
        "python-perf-2.6.32-642.13.1.vl6"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
