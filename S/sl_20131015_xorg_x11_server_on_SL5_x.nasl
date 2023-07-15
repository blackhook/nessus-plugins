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
  script_id(70468);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4396");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL5.x, SL6.x i386/x86_64 (20131015)");
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
"A use-after-free flaw was found in the way the X.Org server handled
ImageText requests. A malicious, authorized client could use this flaw
to crash the X.Org server or, potentially, execute arbitrary code with
root privileges. (CVE-2013-4396)

Users of proprietary drivers may need to reinstall the driver after
applying this update. Some users have reported the inability to load X
without reloading the nVidia or the ATI drivers. You can use 'yum
reinstall' to easily reload drivers packaged in RPM format. RPMs for
many common drivers can be found at the ELRepo Project. You can easily
add the ELRepo Project's repository to your system with 'yum install
yum-conf-elrepo' on SL 6 systems. Any issues with ELRepo packages
should be directed to their mailing lists.

After installing the update, X must be restarted for the changes to
take full effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=1412
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?441959dd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-evdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-i810");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-i810-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-keyboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-mach64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-mga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-mutouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-nv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-sis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-synaptics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-synaptics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvnc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xinit");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");
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
if (rpm_check(release:"SL5", reference:"xorg-x11-drivers-7.1-4.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-ast-0.89.9-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-evdev-1.0.0.5-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-fbdev-0.3.0-3")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-i810-1.6.5-9.40.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-i810-devel-1.6.5-9.40.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-keyboard-1.1.0-3")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-mga-1.4.13-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-mutouch-1.1.0-3")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-nv-2.1.15-4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-qxl-0.0.12-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-sis-0.9.1-7.3.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-drv-vesa-1.3.0-8.3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-font-utils-7.1-3")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-proto-devel-7.1-13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xnest-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xorg-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-debuginfo-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-sdk-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-utils-7.1-5.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-xdm-1.0.5-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-xfs-1.0.2-5.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-xfs-utils-1.0.2-5.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-xinit-1.0.2-15.el5")) flag++;

if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mach64-6.9.3-4.1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mga-1.6.1-8.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-synaptics-1.6.2-11.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-synaptics-devel-1.6.2-11.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-debuginfo-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.13.0-11.1.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.13.0-11.1.sl6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-drivers / xorg-x11-drv-ast / xorg-x11-drv-evdev / etc");
}
