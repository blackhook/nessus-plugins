#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2390 and 
# CentOS Errata and Security Advisory 2018:2390 respectively.
#

include("compat.inc");

if (description)
{
  script_id(111704);
  script_version("1.9");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-0861", "CVE-2017-15265", "CVE-2018-1000004", "CVE-2018-10901", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-3693", "CVE-2018-5390", "CVE-2018-7566");
  script_xref(name:"RHSA", value:"2018:2390");

  script_name(english:"CentOS 6 : kernel (CESA-2018:2390) (Foreshadow)");
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

[Updated 16th August 2018] The original errata text was missing
reference to CVE-2018-5390 fix. We have updated the errata text to
correct this issue. No changes have been made to the packages.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Modern operating systems implement virtualization of physical memory
to efficiently use available system resources and provide inter-domain
protection through access control and isolation. The L1TF issue was
found in the way the x86 microprocessor designs have implemented
speculative execution of instructions (a commonly used performance
optimisation) in combination with handling of page-faults caused by
terminated virtual to physical address resolving process. As a result,
an unprivileged attacker could use this flaw to read privileged memory
of the kernel or other processes and/or cross guest/host boundaries to
read host memory by conducting targeted cache side-channel attacks.
(CVE-2018-3620, CVE-2018-3646)

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of
instructions past bounds check. The flaw relies on the presence of a
precisely-defined instruction sequence in the privileged code and the
fact that memory writes occur to an address which depends on the
untrusted value. Such writes cause an update into the microprocessor's
data cache even for speculatively executed instructions that never
actually commit (retire). As a result, an unprivileged attacker could
use this flaw to influence speculative execution and/or read
privileged memory by conducting targeted cache side-channel attacks.
(CVE-2018-3693)

* A flaw named SegmentSmack was found in the way the Linux kernel
handled specially crafted TCP packets. A remote attacker could use
this flaw to trigger time and calculation expensive calls to
tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() functions by
sending specially modified packets within ongoing TCP sessions which
could lead to a CPU saturation and hence a denial of service on the
system. Maintaining the denial of service condition requires
continuous two-way TCP sessions to a reachable open port, thus the
attacks cannot be performed using spoofed IP addresses.
(CVE-2018-5390)

* kernel: kvm: vmx: host GDT limit corruption (CVE-2018-10901)

* kernel: Use-after-free in snd_pcm_info function in ALSA subsystem
potentially leads to privilege escalation (CVE-2017-0861)

* kernel: Use-after-free in snd_seq_ioctl_create_port()
(CVE-2017-15265)

* kernel: race condition in snd_seq_write() may lead to UAF or
OOB-access (CVE-2018-7566)

* kernel: Race condition in sound system can lead to denial of service
(CVE-2018-1000004)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Intel OSSIRT (Intel.com) for reporting
CVE-2018-3620 and CVE-2018-3646; Vladimir Kiriansky (MIT) and Carl
Waldspurger (Carl Waldspurger Consulting) for reporting CVE-2018-3693;
Juha-Matti Tilli (Aalto University, Department of Communications and
Networking and Nokia Bell Labs) for reporting CVE-2018-5390; and
Vegard Nossum (Oracle Corporation) for reporting CVE-2018-10901.

Bug Fix(es) :

* The Least recently used (LRU) operations are batched by caching
pages in per-cpu page vectors to prevent contention of the heavily
used lru_lock spinlock. The page vectors can hold even the compound
pages. Previously, the page vectors were cleared only if they were
full. Subsequently, the amount of memory held in page vectors, which
is not reclaimable, was sometimes too high. Consequently the page
reclamation started the Out of Memory (OOM) killing processes. With
this update, the underlying source code has been fixed to clear LRU
page vectors each time when a compound page is added to them. As a
result, OOM killing processes due to high amounts of memory held in
page vectors no longer occur. (BZ#1575819)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-August/022983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b134625a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5390");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-754.3.5.el6")) flag++;


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
