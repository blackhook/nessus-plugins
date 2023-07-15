#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3843. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119758);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2018-14646");
  script_xref(name:"RHSA", value:"2018:3843");

  script_name(english:"RHEL 7 : kernel (RHSA-2018:3843)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.5
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: NULL pointer dereference in
af_netlink.c:__netlink_ns_capable() allows for denial of service
(CVE-2018-14646)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Christian Brauner for reporting this
issue.

Bug Fix(es) :

* Previously, the kernel architectures for IBM z Systems were missing
support to display the status of the Spectre v2 mitigations. As a
consequence, the /sys/devices/system/cpu/vulnerabilities/spectre_v2
file did not exist. With this update, the kernel now shows the status
in the above mentioned file and as a result, the file now reports
either 'Vulnerable' or 'Mitigation: execute trampolines' message.
(BZ#1636884)

* Previously, under certain conditions, the page direct reclaim code
was occasionally stuck in a loop when waiting for the reclaim to
finish. As a consequence, affected applications became unresponsive
with no progress possible. This update fixes the bug by modifying the
page direct reclaim code to bound the waiting time for the reclaim to
finish. As a consequence, the affected applications no longer hang in
the described scenario. (BZ# 1635132)

* Previously, a packet was missing the User Datagram Protocol (UDP)
payload checksum during a full checksum computation, if the hardware
checksum was not applied. As a consequence, a packet with an incorrect
checksum was dropped by a peer. With this update, the kernel includes
the UDP payload checksum during the full checksum computation. As a
result, the checksum is computed correctly and the packet can be
received by the peer. (BZ#1635796)

* Previously, on user setups running a mixed workload, the scheduler
did not pick up tasks because the runqueues were throttled for a long
time. As a consequence, the system became partially unresponsive. To
fix this bug, the kernel now sets a flag in the cfs_bandwidth struct
to secure better task distribution. As a result, the system no longer
becomes unresponsive in the described scenario. (BZ#1640676)

* Previously, clearing a CPU mask with the cgroups feature triggered
the following warning :

kernel: WARNING: CPU: 422 PID: 364940 at kernel/cpuset.c:955
update_cpumasks_hier+0x3af/0x410

As a consequence, the user's log file was flooded with similar warning
messages as above. This update fixes the bug and the warning message
no longer appears in the described scenario. (BZ#1644237)

* Previously, a lot of CPU time was occasionally spent in the kernel
during a teardown of a container with a lot of memory assigned. As a
consequence, an increased risk of CPU soft lockups could occur due to
higher latency of a CPU scheduler for other processes during the
container teardown. To fix the problem, the kernel now adds a
reschedule to the tight kernel loop. As a result, the CPU scheduler
latency is not increased by the container teardown and there is not
the increased risk of CPU soft lockups in the described scenario.
(BZ#1644672)

* When a user created a VLAN device, the kernel set the
wanted_features set of the VLAN to the current features of the base
device. As a consequence, when the base device got new features, the
features were not propagated to the VLAN device. This update fixes the
bug and the VLAN device receives the new features in the described
scenario.

Note that this only affects TCP Segmentation Offload (TSO).
(BZ#1644674)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:3843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14646"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-14646");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:3843");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3843";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", reference:"kernel-abi-whitelists-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-devel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-devel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", reference:"kernel-doc-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-headers-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-headers-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"perf-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"perf-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"perf-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"python-perf-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"python-perf-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-862.25.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-862.25.3.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
