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
  script_id(61318);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Scientific Linux Security Update : tzdata on SL5.x, SL6.x i386/x86_64 (20120523)");
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
"This update adds the following enhancements :

  - The following time-zone changes have been added to the
    zone info database: Haiti entered a period of Daylight
    Saving Time (DST) on March 11; Gaza Strip, West Bank and
    Syria entered a period of DST on March 30.

This update has been placed in the security tree to avoid timezone
related problems such as ntp sync errors."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=1620
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?513af370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata and / or tzdata-java packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tzdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tzdata-java");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL5", reference:"tzdata-2012c-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tzdata-java-2012c-1.el5")) flag++;

if (rpm_check(release:"SL6", reference:"tzdata-2012c-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tzdata-java-2012c-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tzdata / tzdata-java");
}
