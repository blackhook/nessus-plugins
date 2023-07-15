#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0627 and 
# CentOS Errata and Security Advisory 2010:0627 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48910);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0431", "CVE-2010-0435", "CVE-2010-2784");
  script_xref(name:"RHSA", value:"2010:0627");

  script_name(english:"CentOS 5 : kvm (CESA-2010:0627)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix three security issues and multiple bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

It was found that QEMU-KVM on the host did not validate all pointers
provided from a guest system's QXL graphics card driver. A privileged
guest user could use this flaw to cause the host to dereference an
invalid pointer, causing the guest to crash (denial of service) or,
possibly, resulting in the privileged guest user escalating their
privileges on the host. (CVE-2010-0431)

A flaw was found in QEMU-KVM, allowing the guest some control over the
index used to access the callback array during sub-page MMIO
initialization. A privileged guest user could use this flaw to crash
the guest (denial of service) or, possibly, escalate their privileges
on the host. (CVE-2010-2784)

A NULL pointer dereference flaw was found when the host system had a
processor with the Intel VT-x extension enabled. A privileged guest
user could use this flaw to trick the host into emulating a certain
instruction, which could crash the host (denial of service).
(CVE-2010-0435)

This update also fixes the following bugs :

* running a 'qemu-img' check on a faulty virtual machine image ended
with a segmentation fault. With this update, the segmentation fault no
longer occurs when running the 'qemu-img' check. (BZ#610342)

* when attempting to transfer a file between two guests that were
joined in the same virtual LAN (VLAN), the receiving guest
unexpectedly quit. With this update, the transfer completes
successfully. (BZ#610343)

* installation of a system was occasionally failing in KVM. This was
caused by KVM using wrong permissions for large guest pages. With this
update, the installation completes successfully. (BZ#616796)

* previously, the migration process would fail for a virtual machine
because the virtual machine could not map all the memory. This was
caused by a conflict that was initiated when a virtual machine was
initially run and then migrated right away. With this update, the
conflict no longer occurs and the migration process no longer fails.
(BZ#618205)

* using a thinly provisioned VirtIO disk on iSCSI storage and
performing a 'qemu-img' check during an 'e_no_space' event returned
cluster errors. With this update, the errors no longer appear.
(BZ#618206)

All KVM users should upgrade to these updated packages, which contain
backported patches to resolve these issues. Note: The procedure in the
Solution section must be performed before this update will take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05fbda20"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-164.el5_5.21")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-164.el5_5.21")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-164.el5_5.21")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-164.el5_5.21")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kvm / kvm-qemu-img / kvm-tools");
}
