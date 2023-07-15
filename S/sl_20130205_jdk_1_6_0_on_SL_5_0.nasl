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
  script_id(64605);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1541", "CVE-2012-3213", "CVE-2012-3342", "CVE-2013-0351", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0430", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0438", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0450", "CVE-2013-1473", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481");

  script_name(english:"Scientific Linux Security Update : jdk-1.6.0 on SL 5.0 - 5.8 (i386 x86_64) (20130205)");
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
"Multiple fixes. (CVE-2012-1541, CVE-2012-3213, CVE-2012-3342,
CVE-2013-0351, CVE-2013-0409, CVE-2013-0419, CVE-2013-0423,
CVE-2013-0424, CVE-2013-0425, CVE-2013-0426, CVE-2013-0427,
CVE-2013-0428, CVE-2013-0429, CVE-2013-0430, CVE-2013-0432,
CVE-2013-0433, CVE-2013-0434, CVE-2013-0435, CVE-2013-0438,
CVE-2013-0440, CVE-2013-0441, CVE-2013-0442, CVE-2013-0443,
CVE-2013-0445, CVE-2013-0446, CVE-2013-0450, CVE-2013-1473,
CVE-2013-1475, CVE-2013-1476, CVE-2013-1478, CVE-2013-1480,
CVE-2013-1481)

As a reminder, the closed source Java6 packages are not present in
Scientific Linux 5.9. Public updates to the closed source package are
being discontinued by upstream. Scientific Linux 6 has never included
the closed source Java packages.

http://www.oracle.com/technetwork/java/eol-135779.html

All running instances of Java must be restarted for the update to take
effect."
  );
  # http://www.oracle.com/technetwork/java/eol-135779.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/technetwork/java/eol-135779.html"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=2157
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?260ac6b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-sun-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jdk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"java-1.6.0-sun-compat-1.6.0.39-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"jdk-1.6.0_39-fcs")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-sun-compat / jdk");
}
