#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(109463);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-1106");

  script_name(english:"Scientific Linux Security Update : PackageKit on SL7.x x86_64 (20180424)");
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

  - PackageKit: authentication bypass allows to install
    signed packages without administrator privileges
    (CVE-2018-1106)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1804&L=scientific-linux-errata&F=&S=&P=9351
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53a3ae85"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:PackageKit-yum-plugin");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-command-not-found-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-cron-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-debuginfo-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-glib-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-glib-devel-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-gstreamer-plugin-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-gtk3-module-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-yum-1.1.5-2.sl7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"PackageKit-yum-plugin-1.1.5-2.sl7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-command-not-found / PackageKit-cron / etc");
}
