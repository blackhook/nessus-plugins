#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0050 and 
# CentOS Errata and Security Advisory 2012:0050 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57667);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0029");
  script_xref(name:"RHSA", value:"2012:0050");

  script_name(english:"CentOS 6 : qemu-kvm (CESA-2012:0050)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix one security issue, one bug, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space
component for running virtual machines using KVM.

A heap overflow flaw was found in the way QEMU-KVM emulated the e1000
network interface card. A privileged guest user in a virtual machine
whose network interface is configured to use the e1000 emulated driver
could use this flaw to crash the host or, possibly, escalate their
privileges on the host. (CVE-2012-0029)

Red Hat would like to thank Nicolae Mogoreanu for reporting this
issue.

This update also fixes the following bug :

* qemu-kvm has a 'scsi' option, to be used, for example, with the
'-device' option: '-device virtio-blk-pci,drive=[drive
name],scsi=off'. Previously, however, it only masked the feature bit,
and did not reject SCSI commands if a malicious guest ignored the
feature bit and issued a request. This update corrects this issue. The
'scsi=off' option can be used to mitigate the virtualization aspect of
CVE-2011-4127 before the RHSA-2011:1849 kernel update is installed on
the host.

This mitigation is only required if you do not have the RHSA-2011:1849
kernel update installed on the host and you are using raw format
virtio disks backed by a partition or LVM volume.

If you run guests by invoking /usr/libexec/qemu-kvm directly, use the
'-global virtio-blk-pci.scsi=off' option to apply the mitigation. If
you are using libvirt, as recommended by Red Hat, and have the
RHBA-2012:0013 libvirt update installed, no manual action is required:
guests will automatically use 'scsi=off'. (BZ#767721)

Note: After installing the RHSA-2011:1849 kernel update, SCSI requests
issued by guests via the SG_IO IOCTL will not be passed to the
underlying block device when using raw format virtio disks backed by a
partition or LVM volume, even if 'scsi=on' is used.

As well, this update adds the following enhancement :

* Prior to this update, qemu-kvm was not built with RELRO or PIE
support. qemu-kvm is now built with full RELRO and PIE support as a
security enhancement. (BZ#767906)

All users of qemu-kvm should upgrade to these updated packages, which
correct these issues and add this enhancement. After installing this
update, shut down all running virtual machines. Once all virtual
machines have shut down, start them again for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-January/018383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c59796dc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0029");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.209.el6_2.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.209.el6_2.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.209.el6_2.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-tools");
}
