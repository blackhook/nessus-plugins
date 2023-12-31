#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1507. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85040);
  script_version("2.13");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2015-3214", "CVE-2015-5154");
  script_xref(name:"RHSA", value:"2015:1507");

  script_name(english:"RHEL 7 : qemu-kvm (RHSA-2015:1507)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

A heap buffer overflow flaw was found in the way QEMU's IDE subsystem
handled I/O buffer access while processing certain ATAPI commands. A
privileged guest user in a guest with the CDROM drive enabled could
potentially use this flaw to execute arbitrary code on the host with
the privileges of the host's QEMU process corresponding to the guest.
(CVE-2015-5154)

An out-of-bounds memory access flaw, leading to memory corruption or
possibly an information leak, was found in QEMU's pit_ioport_read()
function. A privileged guest user in a QEMU guest, which had QEMU PIT
emulation enabled, could potentially, in rare cases, use this flaw to
execute arbitrary code on the host with the privileges of the hosting
QEMU process. (CVE-2015-3214)

Red Hat would like to thank Matt Tait of Google's Project Zero
security team for reporting the CVE-2015-3214 issue. The CVE-2015-5154
issue was discovered by Kevin Wolf of Red Hat.

This update also fixes the following bug :

* Due to an incorrect implementation of portable memory barriers, the
QEMU emulator in some cases terminated unexpectedly when a virtual
disk was under heavy I/O load. This update fixes the implementation in
order to achieve correct synchronization between QEMU's threads. As a
result, the described crash no longer occurs. (BZ#1233643)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3214"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1507";
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
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcacard-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcacard-devel-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-img-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qemu-kvm-debuginfo-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-86.el7_1.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-86.el7_1.5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-img / qemu-kvm / etc");
  }
}
