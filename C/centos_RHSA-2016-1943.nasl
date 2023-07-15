#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1943 and 
# CentOS Errata and Security Advisory 2016:1943 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93778);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-3710", "CVE-2016-5403");
  script_xref(name:"RHSA", value:"2016:1943");

  script_name(english:"CentOS 5 : kvm (CESA-2016:1943)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kvm is now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

KVM (for Kernel-based Virtual Machine) is a full virtualization
solution for Linux on x86 hardware. Using KVM, one can run multiple
virtual machines running unmodified Linux or Windows images. Each
virtual machine has private virtualized hardware: a network card,
disk, graphics adapter, etc.

Security Fix(es) :

* An out-of-bounds read/write access flaw was found in the way QEMU's
VGA emulation with VESA BIOS Extensions (VBE) support performed
read/write operations using I/O port methods. A privileged guest user
could use this flaw to execute arbitrary code on the host with the
privileges of the host's QEMU process. (CVE-2016-3710)

* Quick Emulator(QEMU) built with the virtio framework is vulnerable
to an unbounded memory allocation issue. It was found that a malicious
guest user could submit more requests than the virtqueue size permits.
Processing a request allocates a VirtQueueElement results in unbounded
memory allocation on the host controlled by the guest. (CVE-2016-5403)

Red Hat would like to thank Wei Xiao (360 Marvel Team) and Qinghao
Tang (360 Marvel Team) for reporting CVE-2016-3710 and hongzhenhao
(Marvel Team) for reporting CVE-2016-5403."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-September/022091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0fdfd291"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3710");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-276.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-debug-83-276.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-276.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-276.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-276.el5.centos")) flag++;


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
