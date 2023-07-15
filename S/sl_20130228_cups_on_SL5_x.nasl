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
  script_id(64963);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5519");

  script_name(english:"Scientific Linux Security Update : cups on SL5.x, SL6.x i386/x86_64 (20130228)");
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
"It was discovered that CUPS administrative users (members of the
SystemGroups groups) who are permitted to perform CUPS configuration
changes via the CUPS web interface could manipulate the CUPS
configuration to gain unintended privileges. Such users could read or
write arbitrary files with the privileges of the CUPS daemon, possibly
allowing them to run arbitrary code with root privileges.
(CVE-2012-5519)

After installing this update, the ability to change certain CUPS
configuration directives remotely will be disabled by default. The
newly introduced ConfigurationChangeRestriction directive can be used
to enable the changing of the restricted directives remotely.

After installing this update, the cupsd daemon will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=6052
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d096996a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-php");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
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
if (rpm_check(release:"SL5", reference:"cups-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-debuginfo-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.3.7-30.el5_9.3")) flag++;

if (rpm_check(release:"SL6", reference:"cups-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"SL6", reference:"cups-debuginfo-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"SL6", reference:"cups-devel-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"SL6", reference:"cups-libs-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"SL6", reference:"cups-lpd-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"SL6", reference:"cups-php-1.4.2-50.el6_4.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-debuginfo / cups-devel / cups-libs / cups-lpd / etc");
}
