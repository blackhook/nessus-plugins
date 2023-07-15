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
  script_id(77465);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0475", "CVE-2014-5119");

  script_name(english:"Scientific Linux Security Update : glibc on SL5.x, SL6.x i386/x86_64 (20140829)");
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
"An off-by-one heap-based buffer overflow flaw was found in glibc's
internal __gconv_translit_find() function. An attacker able to make an
application call the iconv_open() function with a specially crafted
argument could possibly use this flaw to execute arbitrary code with
the privileges of that application. (CVE-2014-5119)

A directory traversal flaw was found in the way glibc loaded locale
files. An attacker able to make an application use a specially crafted
locale name value (for example, specified in an LC_* environment
variable) could possibly use this flaw to execute arbitrary code with
the privileges of that application. (CVE-2014-0475)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1408&L=scientific-linux-errata&T=0&P=1436
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1bde0d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"glibc-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-common-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-debuginfo-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-debuginfo-common-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-devel-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-headers-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-utils-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"SL5", reference:"nscd-2.5-118.el5_10.3")) flag++;

if (rpm_check(release:"SL6", reference:"glibc-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.132.el6_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
