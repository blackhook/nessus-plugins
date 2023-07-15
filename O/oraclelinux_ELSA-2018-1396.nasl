#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1396 and 
# Oracle Linux Security Advisory ELSA-2018-1396 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109808);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-1064", "CVE-2018-5748");
  script_xref(name:"RHSA", value:"2018:1396");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2018-1396)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:1396 :

An update for libvirt is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The libvirt library contains a C API for managing and interacting with
the virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

Security Fix(es) :

* libvirt: Resource exhaustion via qemuMonitorIORead() method
(CVE-2018-5748)

* libvirt: Incomplete fix for CVE-2018-5748 triggered by QEMU guest
agent (CVE-2018-1064)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2018-1064 issue was discovered by Daniel P. Berrange (Red
Hat) and the CVE-2018-5748 issue was discovered by Daniel P. Berrange
(Red Hat) and Peter Krempa (Red Hat).

Bug Fix(es) :

* Previously, the check for a non-unique device boot order did not
properly handle updates of existing devices when a new device was
attached to a guest. Consequently, updating any device with a
specified boot order failed. With this update, the duplicity check
detects correctly handles updates and ignores the original device,
which avoids reporting false conflicts. As a result, updating a device
with a boot order succeeds. (BZ# 1557922)

* In Red Hat Enterprise Linux 7.5, guests with SCSI passthrough
enabled failed to boot because of changes in kernel CGroup detection.
With this update, libvirt fetches dependencies and adds them to the
device CGroup. As a result, and the affected guests now start as
expected. (BZ#1564996)

* The VMX parser in libvirt did not parse more than four network
interfaces. As a consequence, the esx driver did not expose more than
four network interface cards (NICs) for guests running ESXi. With this
update, the VMX parser parses all the available NICs in .vmx files. As
a result, libvirt reports all the NICs of guests running ESXi.
(BZ#1566524)

* Previously, user aliases for PTY devices that were longer than 32
characters were not supported. Consequently, if a domain included a
PTY device with a user alias longer than 32 characters, the domain
would not start. With this update, a static buffer was replaced with a
dynamic buffer. As a result, the domain starts even if the length of
the user alias for a PTY device is longer than 32 characters.
(BZ#1566525)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-May/007696.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-admin-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-client-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-devel-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-docs-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-libs-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-login-shell-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-nss-3.9.0-14.el7_5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-client / libvirt-daemon / etc");
}
