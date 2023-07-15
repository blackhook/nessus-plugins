#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1023.
#

include("compat.inc");

if (description)
{
  script_id(110197);
  script_version("1.7");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-13215", "CVE-2017-16939", "CVE-2018-1000199", "CVE-2018-10675", "CVE-2018-1068", "CVE-2018-1087", "CVE-2018-10901", "CVE-2018-1091", "CVE-2018-1108", "CVE-2018-7995", "CVE-2018-8897");
  script_xref(name:"ALAS", value:"2018-1023");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2018-1023)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A weakness was found in the Linux kernel's implementation of random
seed data. Programs, early in the boot sequence, could use the data
allocated for the seed before it was sufficiently generated.
(CVE-2018-1108)

A flaw was found in the way the Linux kernel handled exceptions
delivered after a stack switch operation via Mov SS or Pop SS
instructions. During the stack switch operation, the processor did not
deliver interrupts and exceptions, rather they are delivered once the
first instruction after the stack switch is executed. An unprivileged
system user could use this flaw to crash the system kernel resulting
in the denial of service. (CVE-2018-8897)

A flaw was found in the Linux kernel's implementation of 32-bit
syscall interface for bridging. This allowed a privileged user to
arbitrarily write to a limited range of kernel memory. (CVE-2018-1068)

The Linux kernel is vulerable to a use-after-free flaw when
Transformation User configuration interface(CONFIG_XFRM_USER)
compile-time configuration were enabled. This vulnerability occurs
while closing a xfrm netlink socket in xfrm_dump_policy_done. A
user/process could abuse this flaw to potentially escalate their
privileges on a system. (CVE-2017-16939)

A flaw was found in the Linux kernel where a crash can be triggered
from unprivileged userspace during core dump on a POWER system with a
certain configuration. This is due to a missing processor feature
check and an erroneous use of transactional memory (TM) instructions
in the core dump path leading to a denial of service.(CVE-2018-1091)

An address corruption flaw was discovered in the Linux kernel built
with hardware breakpoint (CONFIG_HAVE_HW_BREAKPOINT) support. While
modifying a h/w breakpoint via 'modify_user_hw_breakpoint' routine, an
unprivileged user/process could use this flaw to crash the system
kernel resulting in DoS OR to potentially escalate privileges on a the
system.(CVE-2018-1000199)

A flaw was found in the way the Linux kernel's KVM hypervisor handled
exceptions delivered after a stack switch operation via Mov SS or Pop
SS instructions. During the stack switch operation, the processor did
not deliver interrupts and exceptions, rather they are delivered once
the first instruction after the stack switch is executed. An
unprivileged KVM guest user could use this flaw to crash the guest or,
potentially, escalate their privileges in the guest.(CVE-2018-1087)

A flaw was found in the Linux kernel's skcipher component, which
affects the skcipher_recvmsg function. Attackers using a specific
input can lead to a privilege escalation.(CVE-2017-13215)

The do_get_mempolicy() function in mm/mempolicy.c in the Linux kernel
allows local users to hit a use-after-free bug via crafted system
calls and thus cause a denial of service (DoS) or possibly have
unspecified other impact. Due to the nature of the flaw, privilege
escalation cannot be fully ruled out.(CVE-2018-10675)

A flaw was found in Linux kernel's KVM virtualization subsystem. The
VMX code does not restore the GDT.LIMIT to the previous host value,
but instead sets it to 64KB. With a corrupted GDT limit a host's
userspace code has an ability to place malicious entries in the GDT,
particularly to the per-cpu variables. An attacker can use this to
escalate their privileges.(CVE-2018-10901)

A race condition in the store_int_with_restart() function in
arch/x86/kernel/cpu/mcheck/mce.c in the Linux kernel allows local
users to cause a denial of service (panic) by leveraging root access
to write to the check_interval file in a
/sys/devices/system/machinecheck/machinecheck<cpu number> directory.
(CVE-2018-7995)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1023.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' then reboot the instance to update your
system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.14.42-52.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.14.42-52.37.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
