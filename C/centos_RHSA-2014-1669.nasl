#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1669 and 
# CentOS Errata and Security Advisory 2014:1669 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78606);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3615");
  script_xref(name:"RHSA", value:"2014:1669");

  script_name(english:"CentOS 7 : qemu-kvm (CESA-2014:1669)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

An information leak flaw was found in the way QEMU's VGA emulator
accessed frame buffer memory for high resolution displays. A
privileged guest user could use this flaw to leak memory contents of
the host to the guest by setting the display to use a high resolution
in the guest. (CVE-2014-3615)

This issue was discovered by Laszlo Ersek of Red Hat.

This update also fixes the following bug :

* This update fixes a regression in the scsi_block_new_request()
function, which caused all read requests to through SG_IO if the host
cache was not used. (BZ#1141189)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-October/020700.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2c69d6f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3615");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-guest-agent-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-img-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-60.el7_0.10")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-60.el7_0.10")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-guest-agent / etc");
}
