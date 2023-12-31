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
  script_id(91809);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-4444", "CVE-2016-4446", "CVE-2016-4989");

  script_name(english:"Scientific Linux Security Update : setroubleshoot and setroubleshoot-plugins on SL7.x x86_64 (20160623)");
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
"The setroubleshoot-plugins package provides a set of analysis plugins
for use with setroubleshoot. Each plugin has the capacity to analyze
SELinux AVC data and system data to provide user friendly reports
describing how to interpret SELinux AVC denials.

Security Fix(es) :

  - Shell command injection flaws were found in the way the
    setroubleshoot executed external commands. A local
    attacker able to trigger certain SELinux denials could
    use these flaws to execute arbitrary code with
    privileges of the setroubleshoot user. (CVE-2016-4989)

  - Shell command injection flaws were found in the way the
    setroubleshoot allow_execmod and allow_execstack plugins
    executed external commands. A local attacker able to
    trigger an execmod or execstack SELinux denial could use
    these flaws to execute arbitrary code with privileges of
    the setroubleshoot user. (CVE-2016-4444, CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos
Malik (Red Hat) and the CVE-2016-4989 issue was discovered by Red Hat
Product Security.

Note: On Scientific Linux 7.0 and 7.1, the setroubleshoot is run with
root privileges. Therefore, these issues could allow an attacker to
execute arbitrary code with root privileges."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=7157
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c8329df"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:setroubleshoot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:setroubleshoot-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"setroubleshoot-3.2.24-4.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"setroubleshoot-debuginfo-3.2.24-4.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"setroubleshoot-plugins-3.0.59-2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"setroubleshoot-server-3.2.24-4.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot / setroubleshoot-debuginfo / setroubleshoot-plugins / etc");
}
