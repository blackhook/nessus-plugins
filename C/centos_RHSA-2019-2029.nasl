#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2029 and 
# CentOS Errata and Security Advisory 2019:2029 respectively.
#

include('compat.inc');

if (description)
{
  script_id(128651);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-7755",
    "CVE-2018-8087",
    "CVE-2018-9363",
    "CVE-2018-9516",
    "CVE-2018-9517",
    "CVE-2018-10853",
    "CVE-2018-13053",
    "CVE-2018-13093",
    "CVE-2018-13094",
    "CVE-2018-13095",
    "CVE-2018-14625",
    "CVE-2018-14734",
    "CVE-2018-15594",
    "CVE-2018-16658",
    "CVE-2018-16885",
    "CVE-2018-18281",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-7222",
    "CVE-2019-9456",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11833"
  );
  script_xref(name:"RHSA", value:"2019:2029");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 7 : kernel (CESA-2019:2029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Kernel: vhost_net: infinite loop while receiving packets leads to
DoS (CVE-2019-3900)

* Kernel: page cache side channel attacks (CVE-2019-5489)

* kernel: Buffer overflow in hidp_process_report (CVE-2018-9363)

* kernel: l2tp: Race condition between pppol2tp_session_create() and
l2tp_eth_create() (CVE-2018-9517)

* kernel: kvm: guest userspace to guest kernel write (CVE-2018-10853)

* kernel: use-after-free Read in vhost_transport_send_pkt
(CVE-2018-14625)

* kernel: use-after-free in ucma_leave_multicast in
drivers/infiniband/core/ ucma.c (CVE-2018-14734)

* kernel: Mishandling of indirect calls weakens Spectre mitigation for
paravirtual guests (CVE-2018-15594)

* kernel: TLB flush happens too late on mremap (CVE-2018-18281)

* kernel: Heap address information leak while using L2CAP_GET_CONF_OPT
(CVE-2019-3459)

* kernel: Heap address information leak while using
L2CAP_PARSE_CONF_RSP (CVE-2019-3460)

* kernel: denial of service vector through vfio DMA mappings
(CVE-2019-3882)

* kernel: fix race condition between mmget_not_zero()/get_task_mm()
and core dumping (CVE-2019-11599)

* kernel: a NULL pointer dereference in drivers/scsi/megaraid/
megaraid_sas_base.c leading to DoS (CVE-2019-11810)

* kernel: fs/ext4/extents.c leads to information disclosure
(CVE-2019-11833)

* kernel: Information exposure in fd_locked_ioctl function in
drivers/block/ floppy.c (CVE-2018-7755)

* kernel: Memory leak in drivers/net/wireless/
mac80211_hwsim.c:hwsim_new_radio_nl() can lead to potential denial of
service (CVE-2018-8087)

* kernel: HID: debug: Buffer overflow in hid_debug_events_read() in
drivers/ hid/hid-debug.c (CVE-2018-9516)

* kernel: Integer overflow in the alarm_timer_nsleep function
(CVE-2018-13053)

* kernel: NULL pointer dereference in lookup_slow function
(CVE-2018-13093)

* kernel: NULL pointer dereference in xfs_da_shrink_inode function
(CVE-2018-13094)

* kernel: NULL pointer dereference in fs/xfs/libxfs/xfs_inode_buf.c
(CVE-2018-13095)

* kernel: Information leak in cdrom_ioctl_drive_status
(CVE-2018-16658)

* kernel: out-of-bound read in memcpy_fromiovecend() (CVE-2018-16885)

* Kernel: KVM: leak of uninitialized stack contents to guest
(CVE-2019-7222)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-September/006197.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c870043");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-9363");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bpftool-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-1062.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-1062.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / kernel / kernel-abi-whitelists / kernel-debug / etc");
}
