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
  script_id(80162);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-7817");

  script_name(english:"Scientific Linux Security Update : glibc on SL7.x x86_64 (20141218)");
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
"It was found that the wordexp() function would perform command
substitution even when the WRDE_NOCMD flag was specified. An attacker
able to provide specially crafted input to an application using the
wordexp() function, and not sanitizing the input correctly, could
potentially use this flaw to execute arbitrary commands with the
credentials of the user running that application. (CVE-2014-7817)

This update also fixes the following bug :

  - Prior to this update, if a file stream that was opened
    in append mode and its underlying file descriptor were
    used at the same time and the file was truncated using
    the ftruncate() function on the file descriptor, a
    subsequent ftell() call on the stream incorrectly
    modified the file offset by seeking to the new end of
    the file. This update ensures that ftell() modifies the
    state of the file stream only when it is in append mode
    and its buffer is not empty. As a result, the described
    incorrect changes to the file offset no longer occur."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=3476
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cba89865"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-common-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-common-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-devel-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-headers-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-static-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-utils-2.17-55.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nscd-2.17-55.el7_0.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
