#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1854 and 
# CentOS Errata and Security Advisory 2018:1854 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(110645);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2012-6701", "CVE-2015-8830", "CVE-2016-8650", "CVE-2017-12190", "CVE-2017-15121", "CVE-2017-18203", "CVE-2017-2671", "CVE-2017-6001", "CVE-2017-7308", "CVE-2017-7616", "CVE-2017-7889", "CVE-2017-8890", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803");
  script_xref(name:"RHSA", value:"2018:1854");

  script_name(english:"CentOS 6 : kernel (CESA-2018:1854) (Spectre)");
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
  # http://lists.centos.org/pipermail/centos-cr-announce/2018-June/005268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0af364ff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");
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

# Temp disable
exit(0, 'Temporarily disabled.');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-754.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-754.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
