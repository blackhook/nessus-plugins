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
  script_id(69796);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4169");

  script_name(english:"Scientific Linux Security Update : gdm on SL5.x i386/srpm/x86_64 (20130905)");
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
"A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged
user could use this flaw to perform a symbolic link attack, giving
them write access to any file, allowing them to escalate their
privileges to root. (CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the
initscripts package was modified to create the affected directory
safely during the system boot process. Therefore, this update will
appear on all systems, however systems without GDM installed are not
affected by this flaw.

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1309&L=scientific-linux-errata&T=0&P=320
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70f85771"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:initscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:initscripts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"gdm-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-debuginfo-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-debuginfo-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-docs-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-8.45.42-2.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-debuginfo / gdm-docs / initscripts / etc");
}
