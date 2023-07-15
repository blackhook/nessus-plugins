#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2444. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102350);
  script_version("3.10");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2015-8970", "CVE-2016-10200", "CVE-2017-2647");
  script_xref(name:"RHSA", value:"2017:2444");

  script_name(english:"RHEL 6 : MRG (RHSA-2017:2444)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel-rt is now available for Red Hat Enterprise MRG 2.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel-rt packages provide the Real Time Linux Kernel, which
enables fine-tuning for systems with extremely high determinism
requirements.

Security Fix(es) :

* A use-after-free flaw was found in the Linux kernel which enables a
race condition in the L2TPv3 IP Encapsulation feature. A local user
could use this flaw to escalate their privileges or crash the system.
(CVE-2016-10200, Important)

* A flaw was found that can be triggered in keyring_search_iterator in
keyring.c if type->match is NULL. A local user could use this flaw to
crash the system or, potentially, escalate their privileges.
(CVE-2017-2647, Important)

* The lrw_crypt() function in 'crypto/lrw.c' in the Linux kernel
before 4.5 allows local users to cause a system crash and a denial of
service by the NULL pointer dereference via accept(2) system call for
AF_ALG socket without calling setkey() first to set a cipher key.
(CVE-2015-8970, Moderate)

Red Hat would like to thank Igor Redko (Virtuozzo) and Andrey Ryabinin
(Virtuozzo) for reporting CVE-2017-2647 and Igor Redko (Virtuozzo) and
Vasily Averin (Virtuozzo) for reporting CVE-2015-8970.

Bug Fix(es) :

* Writing model-specific register (MSR) registers during intel_idle
initialization could previously cause exceptions. Consequently, a
kernel panic occurred during this initialization. The function call to
write to the MSR with exception handling was modified to use
wrmsrl_safe() instead of wrmsrl(). In this scenario, the kernel no
longer panics. (BZ#1447438)

* The ixgbe driver was using incorrect bitwise operations on received
PTP flags. Consequently, systems that were using the ixgbe driver
could not synchronize time using PTP. The provided patch corrected the
bitwise operations on received PTP flags allowing these system to
correctly synchronize time using PTP. (BZ#1469795) (BZ#1451821)

The kernel-rt packages have been upgraded to version
3.10.0-514.rt56.230, which provides a number of security and bug fixes
over the previous version. (BZ#1463427)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2647"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2015-8970", "CVE-2016-10200", "CVE-2017-2647");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2017:2444");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2444";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.10.0-514.rt56.231.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.10.0-514.rt56.231.el6")) flag++;

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
