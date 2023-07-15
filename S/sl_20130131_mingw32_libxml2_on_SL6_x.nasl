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
  script_id(64425);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3102", "CVE-2011-3905", "CVE-2011-3919", "CVE-2012-0841", "CVE-2012-5134");

  script_name(english:"Scientific Linux Security Update : mingw32-libxml2 on SL6.x (x86_64) (20130131)");
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
"IMPORTANT NOTE: The mingw32 packages in Scientific Linux 6 will no
longer be updated proactively and will be deprecated with the release
of Scientific Linux 6.4. These packages were provided to support other
capabilities in Scientific Linux and were not intended for direct use.
You are advised to not use these packages with immediate effect.

A heap-based buffer overflow flaw was found in the way libxml2 decoded
entity references with long names. A remote attacker could provide a
specially crafted XML file that, when opened in an application linked
against libxml2, would cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3919)

A heap-based buffer underflow flaw was found in the way libxml2
decoded certain entities. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-5134)

It was found that the hashing routine used by libxml2 arrays was
susceptible to predictable hash collisions. Sending a specially
crafted message to an XML service could result in longer processing
time, which could lead to a denial of service. To mitigate this issue,
randomization has been added to the hashing function to reduce the
chance of an attacker successfully causing intentional collisions.
(CVE-2012-0841)

Multiple flaws were found in the way libxml2 parsed certain XPath (XML
Path Language) expressions. If an attacker were able to supply a
specially crafted XML file to an application using libxml2, as well as
an XPath expression for that application to run against the crafted
file, it could cause the application to crash. (CVE-2010-4008,
CVE-2010-4494, CVE-2011-2821, CVE-2011-2834)

Two heap-based buffer overflow flaws were found in the way libxml2
decoded certain XML files. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2011-0216, CVE-2011-3102)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way libxml2 parsed certain XPath expressions. If an
attacker were able to supply a specially crafted XML file to an
application using libxml2, as well as an XPath expression for that
application to run against the crafted file, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2011-1944)

An out-of-bounds memory read flaw was found in libxml2. A remote
attacker could provide a specially crafted XML file that, when opened
in an application linked against libxml2, would cause the application
to crash. (CVE-2011-3905)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=333
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf695f37"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected mingw32-libxml2, mingw32-libxml2-debuginfo and /
or mingw32-libxml2-static packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mingw32-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mingw32-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mingw32-libxml2-static");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"mingw32-libxml2-2.7.6-6.el6_3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"mingw32-libxml2-debuginfo-2.7.6-6.el6_3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"mingw32-libxml2-static-2.7.6-6.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw32-libxml2 / mingw32-libxml2-debuginfo / etc");
}
