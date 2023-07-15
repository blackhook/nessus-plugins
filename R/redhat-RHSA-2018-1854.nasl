#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1854. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110600);
  script_version("1.11");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2012-6701", "CVE-2015-8830", "CVE-2016-8650", "CVE-2017-12190", "CVE-2017-15121", "CVE-2017-18203", "CVE-2017-2671", "CVE-2017-6001", "CVE-2017-7308", "CVE-2017-7616", "CVE-2017-7889", "CVE-2017-8890", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803");
  script_xref(name:"RHSA", value:"2018:1854");

  script_name(english:"RHEL 6 : kernel (RHSA-2018:1854) (Spectre)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of Load
& Store instructions (a commonly used performance optimization). It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory read from address
to which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks. (CVE-2018-3639, PowerPC)

* kernel: net/packet: overflow in check for priv area size
(CVE-2017-7308)

* kernel: AIO interface didn't use rw_verify_area() for checking
mandatory locking on files and size of access (CVE-2012-6701)

* kernel: AIO write triggers integer overflow in some protocols
(CVE-2015-8830)

* kernel: NULL pointer dereference via keyctl (CVE-2016-8650)

* kernel: ping socket / AF_LLC connect() sin_family race
(CVE-2017-2671)

* kernel: Race condition between multiple sys_perf_event_open() calls
(CVE-2017-6001)

* kernel: Incorrect error handling in the set_mempolicy and mbind
compat syscalls in mm/mempolicy.c (CVE-2017-7616)

* kernel: mm subsystem does not properly enforce the
CONFIG_STRICT_DEVMEM protection mechanism (CVE-2017-7889)

* kernel: Double free in the inet_csk_clone_lock function in net/ipv4/
inet_connection_sock.c (CVE-2017-8890)

* kernel: net: sctp_v6_create_accept_sk function mishandles
inheritance (CVE-2017-9075)

* kernel: net: IPv6 DCCP implementation mishandles inheritance
(CVE-2017-9076)

* kernel: net: tcp_v6_syn_recv_sock function mishandles inheritance
(CVE-2017-9077)

* kernel: memory leak when merging buffers in SCSI IO vectors
(CVE-2017-12190)

* kernel: vfs: BUG in truncate_inode_pages_range() and fuse client
(CVE-2017-15121)

* kernel: Race condition in drivers/md/dm.c:dm_get_from_kobject()
allows local users to cause a denial of service (CVE-2017-18203)

* kernel: a NULL pointer dereference in
net/dccp/output.c:dccp_write_xmit() leads to a system crash
(CVE-2018-1130)

* kernel: Missing length check of payload in net/sctp/
sm_make_chunk.c:_sctp_make_chunk() function allows denial of service
(CVE-2018-5803)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Ken Johnson (Microsoft Security Response
Center) and Jann Horn (Google Project Zero) for reporting
CVE-2018-3639; Vitaly Mayatskih for reporting CVE-2017-12190; and
Evgenii Shatokhin (Virtuozzo Team) for reporting CVE-2018-1130. The
CVE-2017-15121 issue was discovered by Miklos Szeredi (Red Hat).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/ssbd"
  );
  # https://access.redhat.com/documentation/en-US/red_hat_enterprise_linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d2572ef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-6001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-8890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-18203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5803"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2012-6701", "CVE-2015-8830", "CVE-2016-8650", "CVE-2017-12190", "CVE-2017-15121", "CVE-2017-18203", "CVE-2017-2671", "CVE-2017-6001", "CVE-2017-7308", "CVE-2017-7616", "CVE-2017-7889", "CVE-2017-8890", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:1854");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1854";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-abi-whitelists-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-754.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-754.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
