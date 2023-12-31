#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1101. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79043);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-7339", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851");
  script_bugtraq_id(66351, 66492, 66543, 66591, 66779);
  script_xref(name:"RHSA", value:"2014:1101");

  script_name(english:"RHEL 6 : kernel (RHSA-2014:1101)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.4 Extended
Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A use-after-free flaw was found in the way the ping_init_sock()
function of the Linux kernel handled the group_info reference counter.
A local, unprivileged user could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-2851,
Important)

* A NULL pointer dereference flaw was found in the
rds_ib_laddr_check() function in the Linux kernel's implementation of
Reliable Datagram Sockets (RDS). A local, unprivileged user could use
this flaw to crash the system. (CVE-2013-7339, Moderate)

* It was found that a remote attacker could use a race condition flaw
in the ath_tx_aggr_sleep() function to crash the system by creating
large network traffic on the system's Atheros 9k wireless network
adapter. (CVE-2014-2672, Moderate)

* A NULL pointer dereference flaw was found in the
rds_iw_laddr_check() function in the Linux kernel's implementation of
Reliable Datagram Sockets (RDS). A local, unprivileged user could use
this flaw to crash the system. (CVE-2014-2678, Moderate)

* A race condition flaw was found in the way the Linux kernel's
mac80211 subsystem implementation handled synchronization between TX
and STA wake-up code paths. A remote attacker could use this flaw to
crash the system. (CVE-2014-2706, Moderate)

This update also fixes the following bugs :

* The Completely Fair Scheduler (CFS) did not verify whether the CFS
period timer is running while throttling tasks on the CFS run queue.
Therefore under certain circumstances, the CFS run queue became stuck
because the CFS period timer was inactive and could not be restarted.
To fix this problem, the CFS now restarts the CFS period timer inside
the throttling function if it is inactive. (BZ#1120666)

* A previous change to the SCSI code fixed a race condition that could
occur when removing a SCSI device. However, that change caused
performance degradation because it used a certain function from the
block layer code that was returning different values compared with
later versions of the kernel. This update alters the SCSI code to
properly utilize the values returned by the block layer code.
(BZ#1117581)

* If a statically defined gateway became unreachable and its
corresponding neighbor entry entered a FAILED state, the gateway
stayed in the FAILED state even after it became reachable again. This
prevented routing of the traffic through that gateway. This update
allows probing such a gateway automatically and routing the traffic
through the gateway again once it becomes reachable. (BZ#1115262)

* A miscalculation in the 'radix_tree' swap encoding corrupted swap
area indexes bigger than 8 by truncating lower bits of swap entries.
Consequently, systems with more than 8 swap areas could trigger a
bogus OOM scenario when swapping out to such a swap area. This update
fixes this problem by reducing a return value of the SWP_TYPE_SHIFT()
function and removing a broken function call from the
read_swap_header() function. (BZ#1099727)

* The automatic route cache rebuilding feature could incorrectly
compute the length of a route hash chain if the cache contained
multiple entries with the same key but a different TOS, mark, or OIF
bit. Consequently, the feature could reach the rebuild limit and
disable the routing cache on the system. This problem is fixed by
using a helper function that avoids counting such duplicate routes.
(BZ#1113823)

* When booting a guest in the Hyper-V environment and enough of
Programmable Interval Timer (PIT) interrupts were lost or not injected
into the guest on time, the kernel panicked and the guest failed to
boot. This problem has been fixed by bypassing the relevant PIT check
when the guest is running under the Hyper-V environment. (BZ#1112225)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-7339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2851"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  cve_list = make_list("CVE-2013-7339", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2014:1101");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1101";
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
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-headers-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"perf-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"perf-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"perf-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"perf-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"python-perf-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"python-perf-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"python-perf-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-358.48.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-358.48.1.el6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}
