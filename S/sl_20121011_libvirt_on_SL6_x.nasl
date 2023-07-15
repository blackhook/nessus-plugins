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
  script_id(62506);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4423");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64 (20121011)");
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
"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

A flaw was found in libvirtd's RPC call handling. An attacker able to
establish a read-only connection to libvirtd could use this flaw to
crash libvirtd by sending an RPC message that has an event as the RPC
number, or an RPC number that falls into a gap in the RPC dispatch
table. (CVE-2012-4423)

This update also fixes the following bugs :

  - When the host_uuid option was present in the
    libvirtd.conf file, the augeas libvirt lens was unable
    to parse the file. This bug has been fixed and the
    augeas libvirt lens now parses libvirtd.conf as expected
    in the described scenario.

  - Disk hot plug is a two-part action: the
    qemuMonitorAddDrive() call is followed by the
    qemuMonitorAddDevice() call. When the first part
    succeeded but the second one failed, libvirt failed to
    roll back the first part and the device remained in use
    even though the disk hot plug failed. With this update,
    the rollback for the drive addition is properly
    performed in the described scenario and disk hot plug
    now works as expected.

  - When a virtual machine was started with an image chain
    using block devices and a block rebase operation was
    issued, the operation failed on completion in the
    blockJobAbort() function. This update relabels and
    configures cgroups for the backing files and the rebase
    operation now succeeds.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1210&L=scientific-linux-errata&T=0&P=1639
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61085f84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"libvirt-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.9.10-21.el6_3.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-devel / libvirt-lock-sanlock / etc");
}
