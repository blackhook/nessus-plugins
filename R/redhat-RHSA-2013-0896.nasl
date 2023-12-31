#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0896. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66771);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-2007");
  script_bugtraq_id(59675);
  script_xref(name:"RHSA", value:"2013:0896");

  script_name(english:"RHEL 6 : qemu-kvm (RHSA-2013:0896)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space
component for running virtual machines using KVM.

It was found that QEMU Guest Agent (the 'qemu-ga' service) created
certain files with world-writable permissions when run in daemon mode
(the default mode). An unprivileged guest user could use this flaw to
consume all free space on the partition containing the qemu-ga log
file, or modify the contents of the log. When a UNIX domain socket
transport was explicitly configured to be used (not the default), an
unprivileged guest user could potentially use this flaw to escalate
their privileges in the guest. This update requires manual action.
Refer below for details. (CVE-2013-2007)

This update does not change the permissions of the existing log file
or the UNIX domain socket. For these to be changed, stop the qemu-ga
service, and then manually remove all 'group' and 'other' permissions
on the affected files, or remove the files.

Note that after installing this update, files created by the
guest-file-open QEMU Monitor Protocol (QMP) command will still
continue to be created with world-writable permissions for backwards
compatibility.

This issue was discovered by Laszlo Ersek of Red Hat.

This update also fixes the following bugs :

* Previously, due to integer overflow in code calculations, the
qemu-kvm utility was reporting incorrect memory size on QMP events
when using the virtio balloon driver with more than 4 GB of memory.
This update fixes the overflow in the code and qemu-kvm works as
expected in the described scenario. (BZ#958750)

* When the set_link flag is set to 'off' to change the status of a
network card, the status is changed to 'down' on the respective guest.
Previously, with certain network cards, when such a guest was
restarted, the status of the network card was unexpectedly reset to
'up', even though the network was unavailable. A patch has been
provided to address this bug and the link status change is now
preserved across restarts for all network cards. (BZ#927591)

All users of qemu-kvm should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, shut down all running virtual machines. Once all virtual
machines have shut down, start them again for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-2007"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent-win32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0896";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qemu-guest-agent-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-guest-agent-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-guest-agent-win32-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qemu-kvm-debuginfo-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-debuginfo-0.12.1.2-2.355.el6_4.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.355.el6_4.5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-guest-agent-win32 / qemu-img / qemu-kvm / etc");
  }
}
