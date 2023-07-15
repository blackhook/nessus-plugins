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
  script_id(91537);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9653");

  script_name(english:"Scientific Linux Security Update : file on SL6.x i386/x86_64 (20160510)");
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

  - Multiple flaws were found in the file regular expression
    rules for detecting various files. A remote attacker
    could use these flaws to cause file to consume an
    excessive amount of CPU. (CVE-2014-3538)

  - A denial of service flaw was found in the way file
    parsed certain Composite Document Format (CDF) files. A
    remote attacker could use this flaw to crash file via a
    specially crafted CDF file. (CVE-2014-3587)

  - Multiple flaws were found in the way file parsed
    Executable and Linkable Format (ELF) files. A remote
    attacker could use these flaws to cause file to crash,
    disclose portions of its memory, or consume an excessive
    amount of system resources. (CVE-2014-3710,
    CVE-2014-8116, CVE-2014-8117, CVE-2014-9620,
    CVE-2014-9653)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=850
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd127452"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"file-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-debuginfo-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-devel-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-libs-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-static-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-magic-5.04-30.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-devel / file-libs / file-static / etc");
}
