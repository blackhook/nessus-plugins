#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65014);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4517", "CVE-2012-4518");

  script_name(english:"Scientific Linux Security Update : rdma on SL6.x i386/x86_64 (20130221)");
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
"A denial of service flaw was found in the way ibacm managed reference
counts for multicast connections. An attacker could send specially
crafted multicast packets that would cause the ibacm daemon to crash.
(CVE-2012-4517)

It was found that the ibacm daemon created some files with
world-writable permissions. A local attacker could use this flaw to
overwrite the contents of the ibacm.log or ibacm.port file, allowing
them to mask certain actions from the log or cause ibacm to run on a
non-default port. (CVE-2012-4518)

The InfiniBand/iWARP/RDMA stack components have been upgraded to more
recent upstream versions.

This update also fixes the following bugs :

  - Previously, the 'ibnodes -h' command did not show a
    proper usage message. With this update the problem is
    fixed and 'ibnodes -h' now shows the correct usage
    message.

  - Previously, the ibv_devinfo utility erroneously showed
    iWARP cxgb3 hardware's physical state as invalid even
    when the device was working. For iWARP hardware, the
    phys_state field has no meaning. This update patches the
    utility to not print out anything for this field when
    the hardware is iWARP hardware.

  - Prior to the release of Scientific Linux 6.3, the kernel
    created the InfiniBand device files in the wrong place
    and a udev rules file was used to force the devices to
    be created in the proper place. With the update to 6.3,
    the kernel was fixed to create the InfiniBand device
    files in the proper place, and so the udev rules file
    was removed as no longer being necessary. However, a bug
    in the kernel device creation meant that, although the
    devices were now being created in the right place, they
    had incorrect permissions. Consequently, when users
    attempted to run an RDMA application as a non-root user,
    the application failed to get the necessary permissions
    to use the RDMA device and the application terminated.
    This update puts a new udev rules file in place. It no
    longer attempts to create the InfiniBand devices since
    they already exist, but it does correct the device
    permissions on the files.

  - Previously, using the 'perfquery -C' command with a host
    name caused the perfquery utility to become
    unresponsive. The list of controllers to process was
    never cleared and the process looped infinitely on a
    single controller. A patch has been applied to make sure
    that in the case where the user passes in the -C option,
    the controller list is cleared out once that controller
    has been processed. As a result, perfquery now works as
    expected in the scenario described.

  - The OpenSM init script did not handle the case where
    there were no configuration files under
    '/etc/rdma/opensm.conf.*'. With this update, the script
    as been patched and the InfiniBand Subnet Manager,
    OpenSM, now starts as expected in the scenario
    described.

This update also adds the following enhancement :

  - This update provides an updated mlx4_ib Mellanox driver
    which includes Single Root I/O Virtualization (SR-IOV)
    support."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=1178
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5711aa05"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibacm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibsim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibsim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infiniband-diags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infiniband-diags-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infiniband-diags-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infiniband-diags-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infinipath-psm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibmad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibmad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibmad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibmad-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibumad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibumad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibumad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibumad-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libibverbs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmlx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmlx4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmlx4-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:librdmacm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rdma");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"ibacm-1.0.8-0.git7a3adb7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibacm-debuginfo-1.0.8-0.git7a3adb7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibacm-devel-1.0.8-0.git7a3adb7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibsim-0.5-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibsim-debuginfo-0.5-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-1.5.7-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-debuginfo-1.5.7-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-devel-1.5.7-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ibutils-libs-1.5.7-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"infiniband-diags-1.5.12-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"infiniband-diags-debuginfo-1.5.12-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"infiniband-diags-devel-1.5.12-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"infiniband-diags-devel-static-1.5.12-5.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"infinipath-psm-3.0.1-115.1015_open.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"infinipath-psm-debuginfo-3.0.1-115.1015_open.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"infinipath-psm-devel-3.0.1-115.1015_open.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibmad-1.3.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibmad-debuginfo-1.3.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibmad-devel-1.3.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibmad-static-1.3.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibumad-1.3.8-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibumad-debuginfo-1.3.8-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibumad-devel-1.3.8-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibumad-static-1.3.8-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-1.1.6-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-debuginfo-1.1.6-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-devel-1.1.6-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-devel-static-1.1.6-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libibverbs-utils-1.1.6-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libmlx4-1.0.4-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libmlx4-debuginfo-1.0.4-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libmlx4-static-1.0.4-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-debuginfo-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-devel-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-static-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"SL6", reference:"librdmacm-utils-1.0.17-0.git4b5c1aa.el6")) flag++;
if (rpm_check(release:"SL6", reference:"opensm-3.3.15-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"opensm-debuginfo-3.3.15-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"opensm-devel-3.3.15-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"opensm-libs-3.3.15-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"opensm-static-3.3.15-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rdma-3.6-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibacm / ibacm-debuginfo / ibacm-devel / ibsim / ibsim-debuginfo / etc");
}
