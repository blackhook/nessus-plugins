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
  script_id(91712);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2016-5118", "CVE-2016-5239", "CVE-2016-5240");

  script_name(english:"Scientific Linux Security Update : ImageMagick on SL6.x, SL7.x i386/x86_64 (20160617)");
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

  - It was discovered that ImageMagick did not properly
    sanitize certain input before using it to invoke
    processes. A remote attacker could create a specially
    crafted image that, when processed by an application
    using ImageMagick or an unsuspecting user using the
    ImageMagick utilities, would lead to arbitrary execution
    of shell commands with the privileges of the user
    running the application. (CVE-2016-5118)

  - It was discovered that ImageMagick did not properly
    sanitize certain input before passing it to the gnuplot
    delegate functionality. A remote attacker could create a
    specially crafted image that, when processed by an
    application using ImageMagick or an unsuspecting user
    using the ImageMagick utilities, would lead to arbitrary
    execution of shell commands with the privileges of the
    user running the application. (CVE-2016-5239)

  - Multiple flaws have been discovered in ImageMagick. A
    remote attacker could, for example, create specially
    crafted images that, when processed by an application
    using ImageMagick or an unsuspecting user using the
    ImageMagick utilities, would result in a memory
    corruption and, potentially, execution of arbitrary
    code, a denial of service, or an application crash.
    (CVE-2015-8896, CVE-2015-8895, CVE-2016-5240,
    CVE-2015-8897, CVE-2015-8898)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=6155
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e7127c7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


flag = 0;
if (rpm_check(release:"SL6", reference:"ImageMagick-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-c++-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-c++-devel-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-debuginfo-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-devel-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-doc-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-perl-6.7.2.7-5.el6_8")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-c++-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-devel-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-doc-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-perl-6.7.8.9-15.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
