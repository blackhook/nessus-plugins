#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3967. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131375);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-18208",
    "CVE-2018-9568",
    "CVE-2018-10902",
    "CVE-2018-18559",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-6974",
    "CVE-2019-7221"
  );
  script_xref(name:"RHSA", value:"2019:3967");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : kernel (RHSA-2019:3967)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.5
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: Memory corruption due to incorrect socket cloning
(CVE-2018-9568)

* kernel: MIDI driver race condition leads to a double-free
(CVE-2018-10902)

* kernel: Use-after-free due to race condition in AF_PACKET
implementation (CVE-2018-18559)

* Kernel: vhost_net: infinite loop while receiving packets leads to
DoS (CVE-2019-3900)

* Kernel: page cache side channel attacks (CVE-2019-5489)

* Kernel: KVM: potential use-after-free via kvm_ioctl_create_device()
(CVE-2019-6974)

* Kernel: KVM: nVMX: use-after-free of the hrtimer for emulation of
the preemption timer (CVE-2019-7221)

* kernel: Inifinite loop vulnerability in
mm/madvise.c:madvise_willneed() function allows local denial of
service (CVE-2017-18208)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* A cluster node has multiple hung 'mv' processes that are accessing a
gfs2 filesystem. (BZ#1716321)

* Growing unreclaimable slab memory (BZ#1741918)

* [LLNL 7.5 Bug] slab leak causing a crash when using kmem control
group (BZ# 1748236)

* kernel build: parallelize redhat/mod-sign.sh (BZ#1755328)

* kernel build: speed up module compression step (BZ#1755337)");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3967");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-18208");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-9568");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10902");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18559");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5489");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-6974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7221");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9568");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-18208", "CVE-2018-10902", "CVE-2018-18559", "CVE-2018-9568", "CVE-2019-3900", "CVE-2019-5489", "CVE-2019-6974", "CVE-2019-7221");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:3967");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3967";
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
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", reference:"kernel-abi-whitelists-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-devel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-devel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", reference:"kernel-doc-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-headers-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-headers-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"perf-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"perf-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"perf-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"python-perf-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"python-perf-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-862.44.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-862.44.2.el7")) flag++;

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
