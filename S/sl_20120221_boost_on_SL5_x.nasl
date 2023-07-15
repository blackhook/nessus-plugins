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
  script_id(61256);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-0171", "CVE-2008-0172");

  script_name(english:"Scientific Linux Security Update : boost on SL5.x i386/x86_64 (20120221)");
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
"The boost packages provide free, peer-reviewed, portable C++ source
libraries with emphasis on libraries which work well with the C++
Standard Library.

Invalid pointer dereference flaws were found in the way the Boost
regular expression library processed certain, invalid expressions. An
attacker able to make an application using the Boost library process a
specially crafted regular expression could cause that application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2008-0171)

NULL pointer dereference flaws were found in the way the Boost regular
expression library processed certain, invalid expressions. An attacker
able to make an application using the Boost library process a
specially crafted regular expression could cause that application to
crash. (CVE-2008-0172)

This update also fixes the following bugs :

  - Prior to this update, the construction of a regular
    expression object could fail when several regular
    expression objects were created simultaneously, such as
    in a multi-threaded program. With this update, the
    object variables have been moved from the shared memory
    to the stack. Now, the constructing function is thread
    safe.

  - Prior to this update, header files in several Boost
    libraries contained preprocessor directives that the GNU
    Compiler Collection (GCC) 4.4 could not handle. This
    update instead uses equivalent constructs that are
    standard C.

All users of boost are advised to upgrade to these updated packages,
which fix these issues."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2917
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11e11709"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-doc");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"boost-1.33.1-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"boost-debuginfo-1.33.1-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"boost-devel-1.33.1-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"boost-doc-1.33.1-15.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "boost / boost-debuginfo / boost-devel / boost-doc");
}
