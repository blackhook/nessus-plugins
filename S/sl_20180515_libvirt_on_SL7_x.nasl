#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(109853);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-1064", "CVE-2018-5748");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x x86_64 (20180515)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - libvirt: Resource exhaustion via qemuMonitorIORead()
    method (CVE-2018-5748)

  - libvirt: Incomplete fix for CVE-2018-5748 triggered by
    QEMU guest agent (CVE-2018-1064)

The CVE-2018-1064 issue was discovered by Daniel P. Berrang (Red Hat)
and the CVE-2018-5748 issue was discovered by Daniel P. Berrange (Red
Hat) and Peter Krempa (Red Hat).

Bug Fix(es) :

  - Previously, the check for a non-unique device boot order
    did not properly handle updates of existing devices when
    a new device was attached to a guest. Consequently,
    updating any device with a specified boot order failed.
    With this update, the duplicity check detects correctly
    handles updates and ignores the original device, which
    avoids reporting false conflicts. As a result, updating
    a device with a boot order succeeds.

  - In Scientific Linux 7.5, guests with SCSI passthrough
    enabled failed to boot because of changes in kernel
    CGroup detection. With this update, libvirt fetches
    dependencies and adds them to the device CGroup. As a
    result, and the affected guests now start as expected.

  - The VMX parser in libvirt did not parse more than four
    network interfaces. As a consequence, the esx driver did
    not expose more than four network interface cards (NICs)
    for guests running ESXi. With this update, the VMX
    parser parses all the available NICs in .vmx files. As a
    result, libvirt reports all the NICs of guests running
    ESXi.

  - Previously, user aliases for PTY devices that were
    longer than 32 characters were not supported.
    Consequently, if a domain included a PTY device with a
    user alias longer than 32 characters, the domain would
    not start. With this update, a static buffer was
    replaced with a dynamic buffer. As a result, the domain
    starts even if the length of the user alias for a PTY
    device is longer than 32 characters."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1805&L=scientific-linux-errata&F=&S=&P=18857
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2123b1e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-admin-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-client-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-debuginfo-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-devel-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-docs-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-libs-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-login-shell-3.9.0-14.el7_5.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-nss-3.9.0-14.el7_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-client / libvirt-daemon / etc");
}
