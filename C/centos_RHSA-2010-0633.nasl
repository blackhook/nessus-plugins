#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0633 and 
# CentOS Errata and Security Advisory 2010:0633 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48911);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0428", "CVE-2010-0429");
  script_xref(name:"RHSA", value:"2010:0633");

  script_name(english:"CentOS 5 : qspice (CESA-2010:0633)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qspice packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol used in Red Hat Enterprise Linux for viewing
virtualized guests running on the Kernel-based Virtual Machine (KVM)
hypervisor, or on Red Hat Enterprise Virtualization Hypervisor.

It was found that the libspice component of QEMU-KVM on the host did
not validate all pointers provided from a guest system's QXL graphics
card driver. A privileged guest user could use this flaw to cause the
host to dereference an invalid pointer, causing the guest to crash
(denial of service) or, possibly, resulting in the privileged guest
user escalating their privileges on the host. (CVE-2010-0428)

It was found that the libspice component of QEMU-KVM on the host could
be forced to perform certain memory management operations on memory
addresses controlled by a guest. A privileged guest user could use
this flaw to crash the guest (denial of service) or, possibly,
escalate their privileges on the host. (CVE-2010-0429)

All qspice users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4140ebe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qspice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qspice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qspice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qspice-libs-devel");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"qspice-0.3.0-54.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"qspice-libs-0.3.0-54.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"qspice-libs-devel-0.3.0-54.el5_5.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qspice / qspice-libs / qspice-libs-devel");
}
