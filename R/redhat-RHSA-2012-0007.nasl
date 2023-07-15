#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0007. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57481);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1020", "CVE-2011-3637", "CVE-2011-4077", "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4325", "CVE-2011-4330", "CVE-2011-4348");
  script_bugtraq_id(46567, 50370, 50663, 50750, 50798, 51092);
  script_xref(name:"RHSA", value:"2012:0007");

  script_name(english:"RHEL 5 : kernel (RHSA-2012:0007)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated kernel packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A buffer overflow flaw was found in the way the Linux kernel's XFS
file system implementation handled links with overly long path names.
A local, unprivileged user could use this flaw to cause a denial of
service or escalate their privileges by mounting a specially crafted
disk. (CVE-2011-4077, Important)

* The fix for CVE-2011-2482 provided by RHSA-2011:1212 introduced a
regression: on systems that do not have Security-Enhanced Linux
(SELinux) in Enforcing mode, a socket lock race could occur between
sctp_rcv() and sctp_accept(). A remote attacker could use this flaw to
cause a denial of service. By default, SELinux runs in Enforcing mode
on Red Hat Enterprise Linux 5. (CVE-2011-4348, Important)

* The proc file system could allow a local, unprivileged user to
obtain sensitive information or possibly cause integrity issues.
(CVE-2011-1020, Moderate)

* A missing validation flaw was found in the Linux kernel's m_stop()
implementation. A local, unprivileged user could use this flaw to
trigger a denial of service. (CVE-2011-3637, Moderate)

* A flaw was found in the Linux kernel's Journaling Block Device
(JBD). A local attacker could use this flaw to crash the system by
mounting a specially crafted ext3 or ext4 disk. (CVE-2011-4132,
Moderate)

* A flaw was found in the Linux kernel's encode_share_access()
implementation. A local, unprivileged user could use this flaw to
trigger a denial of service by creating a regular file on an NFSv4
(Network File System version 4) file system via mknod().
(CVE-2011-4324, Moderate)

* A flaw was found in the Linux kernel's NFS implementation. A local,
unprivileged user could use this flaw to cause a denial of service.
(CVE-2011-4325, Moderate)

* A missing boundary check was found in the Linux kernel's HFS file
system implementation. A local attacker could use this flaw to cause a
denial of service or escalate their privileges by mounting a specially
crafted disk. (CVE-2011-4330, Moderate)

Red Hat would like to thank Kees Cook for reporting CVE-2011-1020, and
Clement Lecigne for reporting CVE-2011-4330.

This update also fixes several bugs and adds one enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  # https://rhn.redhat.com/errata/RHSA-2011-1212.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:1212"
  );
  # https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?056c0c27"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:0007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-3637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4077"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2011-1020", "CVE-2011-3637", "CVE-2011-4077", "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4325", "CVE-2011-4330", "CVE-2011-4348");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2012:0007");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0007";
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
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"kernel-doc-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kernel-headers-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-headers-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-devel-2.6.18-274.17.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-274.17.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
  }
}
