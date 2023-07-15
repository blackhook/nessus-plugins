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
  script_id(65654);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0254");

  script_name(english:"Scientific Linux Security Update : qt on SL6.x i386/x86_64 (20130321)");
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
"It was discovered that the QSharedMemory class implementation of the
Qt toolkit created shared memory segments with insecure permissions. A
local attacker could use this flaw to read or alter the contents of a
particular shared memory segment, possibly leading to their ability to
obtain sensitive information or influence the behavior of a process
that is using the shared memory segment. (CVE-2013-0254)

All running applications linked against Qt libraries must be restarted
for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=5398
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86f58286"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:phonon-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-x11");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/22");
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


flag = 0;
if (rpm_check(release:"SL6", reference:"phonon-backend-gstreamer-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-debuginfo-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-demos-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-devel-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-doc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-examples-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-mysql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-odbc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-postgresql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-sqlite-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-x11-4.6.2-26.el6_4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phonon-backend-gstreamer / qt / qt-debuginfo / qt-demos / qt-devel / etc");
}
