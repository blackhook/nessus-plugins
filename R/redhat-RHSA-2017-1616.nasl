#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1616. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101102);
  script_version("3.15");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-1000364", "CVE-2017-1000379", "CVE-2017-2583", "CVE-2017-6214", "CVE-2017-7477", "CVE-2017-7645", "CVE-2017-7895");
  script_xref(name:"RHSA", value:"2017:1616");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2017:1616) (Stack Clash)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel-rt is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel-rt packages provide the Real Time Linux Kernel, which
enables fine-tuning for systems with extremely high determinism
requirements.

Security Fix(es) :

* A flaw was found in the way memory was being allocated on the stack
for user space binaries. If heap (or different memory region) and
stack memory regions were adjacent to each other, an attacker could
use this flaw to jump over the stack guard gap, cause controlled
memory corruption on process stack or the adjacent memory region, and
thus increase their privileges on the system. This is a kernel-side
mitigation which increases the stack guard gap size from one page to 1
MiB to make successful exploitation of this issue more difficult.
(CVE-2017-1000364, Important)

* A flaw was found in the way Linux kernel allocates heap memory to
build the scattergather list from a fragment
list(skb_shinfo(skb)->frag_list) in the socket buffer(skb_buff). The
heap overflow occurred if 'MAX_SKB_FRAGS + 1' parameter and
'NETIF_F_FRAGLIST' feature are both used together. A remote user or
process could use this flaw to potentially escalate their privilege on
a system. (CVE-2017-7477, Important)

* The NFS2/3 RPC client could send long arguments to the NFS server.
These encoded arguments are stored in an array of memory pages, and
accessed using pointer variables. Arbitrarily long arguments could
make these pointers point outside the array and cause an out-of-bounds
memory access. A remote user or program could use this flaw to crash
the kernel, resulting in denial of service. (CVE-2017-7645, Important)

* The NFSv2 and NFSv3 server implementations in the Linux kernel
through 4.10.13 lacked certain checks for the end of a buffer. A
remote attacker could trigger a pointer-arithmetic error or possibly
cause other unspecified impacts using crafted requests related to
fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important)

* Linux kernel built with the Kernel-based Virtual Machine
(CONFIG_KVM) support was vulnerable to an incorrect segment
selector(SS) value error. The error could occur while loading values
into the SS register in long mode. A user or process inside a guest
could use this flaw to crash the guest, resulting in DoS or
potentially escalate their privileges inside the guest.
(CVE-2017-2583, Moderate)

* A flaw was found in the Linux kernel's handling of packets with the
URG flag. Applications using the splice() and tcp_splice_read()
functionality could allow a remote attacker to force the kernel to
enter a condition in which it could loop indefinitely. (CVE-2017-6214,
Moderate)

Red Hat would like to thank Qualys Research Labs for reporting
CVE-2017-1000364; Ari Kauppi for reporting CVE-2017-7895; and Xiaohan
Zhang (Huawei Inc.) for reporting CVE-2017-2583.

Bug Fix(es) :

* The kernel-rt packages have been upgraded to the 3.10.0-514.25.2
source tree, which provides a number of bug fixes over the previous
version. (BZ# 1452742)

* Previously, a local lock acquisition around the
ip_send_unicast_reply() function was incorrectly terminated.
Consequently, a list corruption occurred that led to a kernel panic.
This update adds locking functions around calls to
ip_send_unicast_reply(). As a result, neither list corruption nor
kernel panic occur under the described circumstances. (BZ# 1455239)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-6214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7895"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'rsh_stack_clash_priv_esc.rb');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-1000364", "CVE-2017-1000379", "CVE-2017-2583", "CVE-2017-6214", "CVE-2017-7477", "CVE-2017-7645", "CVE-2017-7895");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2017:1616");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1616";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-kvm-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-kvm-debuginfo-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-devel-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-rt-doc-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-kvm-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-kvm-debuginfo-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-kvm-3.10.0-514.26.1.rt56.442.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-kvm-debuginfo-3.10.0-514.26.1.rt56.442.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
