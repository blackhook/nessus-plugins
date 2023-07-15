#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3200 and 
# CentOS Errata and Security Advisory 2017:3200 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104583);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-14106");
  script_xref(name:"RHSA", value:"2017:3200");

  script_name(english:"CentOS 6 : kernel (CESA-2017:3200)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A race condition issue leading to a use-after-free flaw was found in
the way the raw packet sockets are implemented in the Linux kernel
networking subsystem handling synchronization. A local user able to
open a raw packet socket (requires the CAP_NET_RAW capability) could
use this flaw to elevate their privileges on the system.
(CVE-2017-1000111, Important)

* An exploitable memory corruption flaw was found in the Linux kernel.
The append path can be erroneously switched from UFO to non-UFO in
ip_ufo_append_data() when building an UFO packet with MSG_MORE option.
If unprivileged user namespaces are available, this flaw can be
exploited to gain root privileges. (CVE-2017-1000112, Important)

* A divide-by-zero vulnerability was found in the __tcp_select_window
function in the Linux kernel. This can result in a kernel panic
causing a local denial of service. (CVE-2017-14106, Moderate)

Red Hat would like to thank Willem de Bruijn for reporting
CVE-2017-1000111 and Andrey Konovalov for reporting CVE-2017-1000112.

Bug Fix(es) :

* When the operating system was booted with Red Hat Enterprise
Virtualization, and the eh_deadline sysfs parameter was set to 10s,
the Storage Area Network (SAN) issues caused eh_deadline to trigger
with no handler. Consequently, a kernel panic occurred. This update
fixes the lpfc driver, thus preventing the kernel panic under
described circumstances. (BZ #1487220)

* When an NFS server returned the NFS4ERR_BAD_SEQID error to an OPEN
request, the open-owner was removed from the state_owners rbtree.
Consequently, NFS4 client infinite loop that required a reboot to
recover occurred. This update changes NFS4ERR_BAD_SEQID handling to
leave the open-owner in the state_owners rbtree by updating the
create_time parameter so that it looks like a new open-owner. As a
result, an NFS4 client is now able to recover without falling into the
infinite recovery loop after receiving NFS4ERR_BAD_SEQID. (BZ#1491123)

* If an NFS client attempted to mount NFSv3 shares from an NFS server
exported directly to the client's IP address, and this NFS client had
already mounted other shares that originated from the same server but
were exported to the subnetwork which this client was part of, the
auth.unix.ip cache expiration was not handled correctly. Consequently,
the client received the 'stale file handle' errors when trying to
mount the share. This update fixes handling of the cache expiration,
and the NFSv3 shares now mount as expected without producing the
'stale file handle' errors. (BZ #1497976)

* When running a script that raised the tx ring count to its maximum
value supported by the Solarflare Network Interface Controller (NIC)
driver, the EF10 family NICs allowed the settings exceeding the
hardware's capability. Consequently, the Solarflare hardware became
unusable with Red Hat Entepripse Linux 6. This update fixes the sfc
driver, so that the tx ring can have maximum 2048 entries for all EF10
NICs. As a result, the Solarflare hardware no longer becomes unusable
with Red Hat Entepripse Linux 6 due to this bug. (BZ#1498019)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-November/022624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88fd3a1f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000111");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-696.16.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-696.16.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
