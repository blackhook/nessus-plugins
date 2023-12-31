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
  script_id(87556);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-7423", "CVE-2015-1472", "CVE-2015-1473", "CVE-2015-1781");

  script_name(english:"Scientific Linux Security Update : glibc on SL7.x x86_64 (20151119)");
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
"It was discovered that, under certain circumstances, glibc's
getaddrinfo() function would send DNS queries to random file
descriptors. An attacker could potentially use this flaw to send DNS
queries to unintended recipients, resulting in information disclosure
or data loss due to the application encountering corrupted data.
(CVE-2013-7423)

A buffer overflow flaw was found in the way glibc's gethostbyname_r()
and other related functions computed the size of a buffer when passed
a misaligned buffer as input. An attacker able to make an application
call any of these functions with a misaligned buffer could use this
flaw to crash the application or, potentially, execute arbitrary code
with the permissions of the user running the application.
(CVE-2015-1781)

A heap-based buffer overflow flaw and a stack overflow flaw were found
in glibc's swscanf() function. An attacker able to make an application
call the swscanf() function could use these flaws to crash that
application or, potentially, execute arbitrary code with the
permissions of the user running the application. (CVE-2015-1472,
CVE-2015-1473)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in glibc's _IO_wstr_overflow() function. An attacker able to
make an application call this function could use this flaw to crash
that application or, potentially, execute arbitrary code with the
permissions of the user running the application.

A flaw was found in the way glibc's fnmatch() function processed
certain malformed patterns. An attacker able to make an application
call this function could use this flaw to crash that application."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=11952
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9cd098a"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-common-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-common-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-devel-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-headers-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-static-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-utils-2.17-105.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nscd-2.17-105.el7")) flag++;


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
