#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1606 and 
# CentOS Errata and Security Advisory 2016:1606 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92951);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5126", "CVE-2016-5403");
  script_xref(name:"RHSA", value:"2016:1606");

  script_name(english:"CentOS 7 : qemu-kvm (CESA-2016:1606)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qemu-kvm is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm packages provide
the user-space component for running virtual machines using KVM.

Security Fix(es) :

* Quick Emulator(Qemu) built with the Block driver for iSCSI images
support (virtio-blk) is vulnerable to a heap buffer overflow issue. It
could occur while processing iSCSI asynchronous I/O ioctl(2) calls. A
user inside guest could use this flaw to crash the Qemu process
resulting in DoS or potentially leverage it to execute arbitrary code
with privileges of the Qemu process on the host. (CVE-2016-5126)

* Quick emulator(Qemu) built with the virtio framework is vulnerable
to an unbounded memory allocation issue. It was found that a malicious
guest user could submit more requests than the virtqueue size permits.
Processing a request allocates a VirtQueueElement and therefore causes
unbounded memory allocation on the host controlled by the guest.
(CVE-2016-5403)

Red Hat would like to thank hongzhenhao (Marvel Team) for reporting
CVE-2016-5403."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-August/022037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e2f5fad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5403");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-1.5.3-105.el7_2.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-105.el7_2.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-105.el7_2.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-img-1.5.3-105.el7_2.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-105.el7_2.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-105.el7_2.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-105.el7_2.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-img / qemu-kvm / etc");
}
