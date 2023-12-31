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
  script_id(65653);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2677");

  script_name(english:"Scientific Linux Security Update : boost on SL5.x, SL6.x i386/x86_64 (20130321)");
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
"A flaw was found in the way the ordered_malloc() routine in Boost
sanitized the 'next_size' and 'max_size' parameters when allocating
memory. If an application used the Boost C++ libraries for memory
allocation, and performed memory allocation based on user-supplied
input, an attacker could use this flaw to crash the application or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-2677)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=5520
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f3ec990"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-date-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-graph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-graph-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-graph-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-iostreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-mpich2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-mpich2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-openmpi-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-program-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-signals");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:boost-wave");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/22");
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
if (rpm_check(release:"SL5", reference:"boost-1.33.1-16.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"boost-debuginfo-1.33.1-16.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"boost-devel-1.33.1-16.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"boost-doc-1.33.1-16.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"boost-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-date-time-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-debuginfo-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-devel-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-doc-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-filesystem-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-graph-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-graph-mpich2-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-graph-openmpi-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-iostreams-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-math-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-mpich2-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-mpich2-devel-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-mpich2-python-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-openmpi-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-openmpi-devel-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-openmpi-python-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-program-options-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-python-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-regex-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-serialization-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-signals-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-static-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-system-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-test-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-thread-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"boost-wave-1.41.0-15.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "boost / boost-date-time / boost-debuginfo / boost-devel / boost-doc / etc");
}
