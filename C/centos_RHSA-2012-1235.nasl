#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1235 and 
# CentOS Errata and Security Advisory 2012:1235 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61790);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-3515");
  script_bugtraq_id(55413);
  script_xref(name:"RHSA", value:"2012:1235");

  script_name(english:"CentOS 5 : kvm (CESA-2012:1235)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix one security issue are now available for
Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

A flaw was found in the way QEMU handled VT100 terminal escape
sequences when emulating certain character devices. A guest user with
privileges to write to a character device that is emulated on the host
using a virtual console back-end could use this flaw to crash the
qemu-kvm process on the host or, possibly, escalate their privileges
on the host. (CVE-2012-3515)

This flaw did not affect the default use of KVM. Affected
configurations were :

* When guests were started from the command line
('/usr/libexec/qemu-kvm'), and without specifying a serial or parallel
device that specifically does not use a virtual console (vc) back-end.
(Note that Red Hat does not support invoking 'qemu-kvm' from the
command line on Red Hat Enterprise Linux 5.)

* Guests that were managed via libvirt, such as when using Virtual
Machine Manager (virt-manager), but that have a serial or parallel
device that uses a virtual console back-end. By default, guests
managed via libvirt will not use a virtual console back-end for such
devices.

Red Hat would like to thank the Xen project for reporting this issue.

All KVM users should upgrade to these updated packages, which correct
this issue. Note: The procedure in the Solution section must be
performed before this update will take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-September/018847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7801d73f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3515");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-249.el5.centos.5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-debug-83-249.el5.centos.5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-249.el5.centos.5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-249.el5.centos.5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-249.el5.centos.5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kmod-kvm-debug / kvm / kvm-qemu-img / kvm-tools");
}
