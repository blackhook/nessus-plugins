#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101411);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-6828",
    "CVE-2016-7117",
    "CVE-2016-9555"
  );

  script_name(english:"Virtuozzo 7 : kernel / kernel-abi-whitelists / kernel-debug / etc (VZLSA-2017-0086)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated kernel packages include several security issues and
numerous bug fixes, some of which you can see below. Space precludes
documenting all of these bug fixes in this advisory. To see the
complete list of bug fixes, users are directed to the related
Knowledge Article: https://access.redhat.com/ articles/2857831.

Security Fix(es) :

* A use-after-free vulnerability was found in the kernel's socket
recvmmsg subsystem. This may allow remote attackers to corrupt memory
and may allow execution of arbitrary code. This corruption takes place
during the error handling routines within __sys_recvmmsg() function.
(CVE-2016-7117, Important)

* A use-after-free vulnerability was found in
tcp_xmit_retransmit_queue and other tcp_* functions. This condition
could allow an attacker to send an incorrect selective acknowledgment
to existing connections, possibly resetting a connection.
(CVE-2016-6828, Moderate)

* A flaw was found in the Linux kernel's implementation of the SCTP
protocol. A remote attacker could trigger an out-of-bounds read with
an offset of up to 64kB potentially causing the system to crash.
(CVE-2016-9555, Moderate)

Bug Fix(es) :

* Previously, the performance of Internet Protocol over InfiniBand
(IPoIB) was suboptimal due to a conflict of IPoIB with the Generic
Receive Offload (GRO) infrastructure. With this update, the data
cached by the IPoIB driver has been moved from a control block into
the IPoIB hard header, thus avoiding the GRO problem and the
corruption of IPoIB address information. As a result, the performance
of IPoIB has been improved. (BZ#1390668)

* Previously, when a virtual machine (VM) with PCI-Passthrough
interfaces was recreated, a race condition between the eventfd daemon
and the virqfd daemon occurred. Consequently, the operating system
rebooted. This update fixes the race condition. As a result, the
operating system no longer reboots in the described situation.
(BZ#1391611)

* Previously, a packet loss occurred when the team driver in
round-robin mode was sending a large number of packets. This update
fixes counting of the packets in the round-robin runner of the team
driver, and the packet loss no longer occurs in the described
situation. (BZ#1392023)

* Previously, the virtual network devices contained in the deleted
namespace could be deleted in any order. If the loopback device was
not deleted as the last item, other netns devices, such as vxlan
devices, could end up with dangling references to the loopback device.
Consequently, deleting a network namespace (netns) occasionally ended
by a kernel oops. With this update, the underlying source code has
been fixed to ensure the correct order when deleting the virtual
network devices on netns deletion. As a result, the kernel oops no
longer occurs under the described circumstances. (BZ#1392024)

* Previously, a Kabylake system with a Sunrise Point Platform
Controller Hub (PCH) with a PCI device ID of 0xA149 showed the
following warning messages during the boot :

'Unknown Intel PCH (0xa149) detected.' 'Warning: Intel Kabylake
processor with unknown PCH - this hardware has not undergone testing
by Red Hat and might not be certified. Please consult https:/
/hardware.redhat.com for certified hardware.'

The messages were shown because this PCH was not properly recognized.
With this update, the problem has been fixed, and the operating system
now boots without displaying the warning messages. (BZ#1392033)

* Previously, the operating system occasionally became unresponsive
after a long run. This was caused by a race condition between the
try_to_wake_up() function and a woken up task in the core scheduler.
With this update, the race condition has been fixed, and the operating
system no longer locks up in the described scenario. (BZ#1393719)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0086.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0751458e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0086");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel / kernel-abi-whitelists / kernel-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.6.1.vl7",
        "kernel-abi-whitelists-3.10.0-514.6.1.vl7",
        "kernel-debug-3.10.0-514.6.1.vl7",
        "kernel-debug-devel-3.10.0-514.6.1.vl7",
        "kernel-devel-3.10.0-514.6.1.vl7",
        "kernel-doc-3.10.0-514.6.1.vl7",
        "kernel-headers-3.10.0-514.6.1.vl7",
        "kernel-tools-3.10.0-514.6.1.vl7",
        "kernel-tools-libs-3.10.0-514.6.1.vl7",
        "kernel-tools-libs-devel-3.10.0-514.6.1.vl7",
        "perf-3.10.0-514.6.1.vl7",
        "python-perf-3.10.0-514.6.1.vl7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
