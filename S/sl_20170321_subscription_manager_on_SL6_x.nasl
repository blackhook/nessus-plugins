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
  script_id(99226);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-4455");

  script_name(english:"Scientific Linux Security Update : subscription-manager on SL6.x i386/x86_64 (20170321)");
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

  - It was found that subscription-manager set weak
    permissions on files in /var/lib/rhsm/, causing an
    information disclosure. A local, unprivileged user could
    use this flaw to access sensitive data that could
    potentially be used in a social engineering attack.
    (CVE-2016-4455)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=4522
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9711e3a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-rhsm-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-rhsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager-firstboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager-migration-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:subscription-manager-plugin-container");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"python-rhsm-1.18.6-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-rhsm-certificates-1.18.6-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-rhsm-debuginfo-1.18.6-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-1.18.10-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-debuginfo-1.18.10-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-firstboot-1.18.10-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-gui-1.18.10-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-migration-1.18.10-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-migration-data-2.0.34-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"subscription-manager-plugin-container-1.18.10-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-rhsm / python-rhsm-certificates / python-rhsm-debuginfo / etc");
}
