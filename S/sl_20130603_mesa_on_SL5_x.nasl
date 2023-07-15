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
  script_id(66778);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1993");

  script_name(english:"Scientific Linux Security Update : mesa on SL5.x i386/x86_64 (20130603)");
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
"It was found that Mesa did not correctly validate messages from the X
server. A malicious X server could cause an application using Mesa to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2013-1993)

All running applications linked against Mesa must be restarted for
this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1306&L=scientific-linux-errata&T=0&P=219
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9d6445c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGLU-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGLw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGLw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-source");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/04");
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


flag = 0;
if (rpm_check(release:"SL5", reference:"glx-utils-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-debuginfo-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libGL-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libGL-devel-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libGLU-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libGLU-devel-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libGLw-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libGLw-devel-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libOSMesa-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-libOSMesa-devel-6.5.1-7.11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"mesa-source-6.5.1-7.11.el5_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glx-utils / mesa-debuginfo / mesa-libGL / mesa-libGL-devel / etc");
}
