#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0928. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78963);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4542", "CVE-2013-0311", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848");
  script_bugtraq_id(58053, 58088, 58177, 58200, 58600, 58604, 58605, 58607);
  script_xref(name:"RHSA", value:"2013:0928");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:0928)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.3 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way the vhost kernel module handled
descriptors that spanned multiple regions. A privileged guest user in
a KVM (Kernel-based Virtual Machine) guest could use this flaw to
crash the host or, potentially, escalate their privileges on the host.
(CVE-2013-0311, Important)

* A buffer overflow flaw was found in the way UTF-8 characters were
converted to UTF-16 in the utf8s_to_utf16s() function of the Linux
kernel's FAT file system implementation. A local user able to mount a
FAT file system with the 'utf8=1' option could use this flaw to crash
the system or, potentially, to escalate their privileges.
(CVE-2013-1773, Important)

* A flaw was found in the way KVM handled guest time updates when the
buffer the guest registered by writing to the MSR_KVM_SYSTEM_TIME
machine state register (MSR) crossed a page boundary. A privileged
guest user could use this flaw to crash the host or, potentially,
escalate their privileges, allowing them to execute arbitrary code at
the host kernel level. (CVE-2013-1796, Important)

* A potential use-after-free flaw was found in the way KVM handled
guest time updates when the GPA (guest physical address) the guest
registered by writing to the MSR_KVM_SYSTEM_TIME machine state
register (MSR) fell into a movable or removable memory region of the
hosting user-space process (by default, QEMU-KVM) on the host. If that
memory region is deregistered from KVM using
KVM_SET_USER_MEMORY_REGION and the allocated virtual memory reused, a
privileged guest user could potentially use this flaw to escalate
their privileges on the host. (CVE-2013-1797, Important)

* A flaw was found in the way KVM emulated IOAPIC (I/O Advanced
Programmable Interrupt Controller). A missing validation check in the
ioapic_read_indirect() function could allow a privileged guest user to
crash the host, or read a substantial portion of host kernel memory.
(CVE-2013-1798, Important)

* It was found that the default SCSI command filter does not
accommodate commands that overlap across device classes. A privileged
guest user could potentially use this flaw to write arbitrary data to
a LUN that is passed-through as read-only. (CVE-2012-4542, Moderate)

* A use-after-free flaw was found in the tmpfs implementation. A local
user able to mount and unmount a tmpfs file system could use this flaw
to cause a denial of service or, potentially, escalate their
privileges. (CVE-2013-1767, Low)

* A format string flaw was found in the ext3_msg() function in the
Linux kernel's ext3 file system implementation. A local user who is
able to mount an ext3 file system could use this flaw to cause a
denial of service or, potentially, escalate their privileges.
(CVE-2013-1848, Low)

Red Hat would like to thank Andrew Honig of Google for reporting the
CVE-2013-1796, CVE-2013-1797, and CVE-2013-1798 issues. The
CVE-2012-4542 issue was discovered by Paolo Bonzini of Red Hat.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1848"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
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
if (! preg(pattern:"^6\.3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.3", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2012-4542", "CVE-2013-0311", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2013:0928");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0928";
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
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-doc-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-firmware-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-headers-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-279.31.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-279.31.1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}
