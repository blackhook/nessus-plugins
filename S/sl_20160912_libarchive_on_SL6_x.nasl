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
  script_id(93453);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8932", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-7166");

  script_name(english:"Scientific Linux Security Update : libarchive on SL6.x i386/x86_64 (20160912)");
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

  - A flaw was found in the way libarchive handled hardlink
    archive entries of non-zero size. Combined with flaws in
    libarchive's file system sandboxing, this issue could
    cause an application using libarchive to overwrite
    arbitrary files with arbitrary data from the archive.
    (CVE-2016-5418)

  - Multiple out-of-bounds read flaws were found in
    libarchive. Specially crafted AR or MTREE files could
    cause the application to read data out of bounds,
    potentially disclosing a small amount of application
    memory, or causing an application crash. (CVE-2015-8920,
    CVE-2015-8921)

  - A denial of service vulnerability was found in
    libarchive's handling of GZIP streams. A crafted GZIP
    file could cause libarchive to allocate an excessive
    amount of memory, eventually leading to a crash.
    (CVE-2016-7166)

  - A denial of service vulnerability was found in
    libarchive. A specially crafted CPIO archive containing
    a symbolic link to a large target path could cause
    memory allocation to fail, causing an application using
    libarchive that attempted to view or extract such
    archive to crash. (CVE-2016-4809)

  - Multiple instances of undefined behavior due to
    arithmetic overflow were found in libarchive. Specially
    crafted Compress streams or ISO9660 volumes could
    potentially cause the application to fail to read the
    archive, or to crash. (CVE-2015-8932, CVE-2016-5844)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1609&L=scientific-linux-errata&F=&S=&P=750
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdda48d4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libarchive, libarchive-debuginfo and / or
libarchive-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libarchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libarchive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");
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
if (rpm_check(release:"SL6", reference:"libarchive-2.8.3-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"libarchive-debuginfo-2.8.3-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"libarchive-devel-2.8.3-7.el6_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libarchive / libarchive-debuginfo / libarchive-devel");
}
