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
  script_id(87062);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5302");

  script_name(english:"Scientific Linux Security Update : libreport on SL6.x i386/x86_64 (20151123)");
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
"It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Bugzilla attachments may contain data that
was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Scientific
Linux as they do not post data to Red Hat Bugzilla."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1511&L=scientific-linux-errata&F=&S=&P=16326
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74cf0aed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"libreport-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-cli-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-compat-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-debuginfo-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-devel-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-filesystem-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-devel-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-newt-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-bugzilla-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-kerneloops-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-logger-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-mailx-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-reportuploader-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-rhtsupport-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-ureport-2.0.9-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-python-2.0.9-25.el6_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreport / libreport-cli / libreport-compat / libreport-debuginfo / etc");
}
