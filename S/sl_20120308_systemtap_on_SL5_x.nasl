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
  script_id(61281);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0875");

  script_name(english:"Scientific Linux Security Update : systemtap on SL5.x, SL6.x i386/x86_64 (20120308)");
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
"SystemTap is an instrumentation system for systems running the Linux
kernel. The system allows developers to write scripts to collect data
on the operation of the system.

An invalid pointer read flaw was found in the way SystemTap handled
malformed debugging information in DWARF format. When SystemTap
unprivileged mode was enabled, an unprivileged user in the stapusr
group could use this flaw to crash the system or, potentially, read
arbitrary kernel memory. Additionally, a privileged user (root, or a
member of the stapdev group) could trigger this flaw when tricked into
instrumenting a specially crafted ELF binary, even when unprivileged
mode was not enabled. (CVE-2012-0875)

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2132
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67637716"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-grapher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"systemtap-1.6-7.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-debuginfo-1.6-7.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-initscript-1.6-7.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-runtime-1.6-7.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-sdt-devel-1.6-7.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-server-1.6-7.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-testsuite-1.6-7.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"systemtap-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-debuginfo-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-grapher-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-initscript-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-runtime-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-sdt-devel-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-server-1.6-5.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"systemtap-testsuite-1.6-5.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-debuginfo / systemtap-grapher / etc");
}
