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
  script_id(86202);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-6908");

  script_name(english:"Scientific Linux Security Update : openldap on SL5.x, SL6.x, SL7.x i386/x86_64 (20150929)");
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
"A flaw was found in the way the OpenLDAP server daemon (slapd) parsed
certain Basic Encoding Rules (BER) data. A remote attacker could use
this flaw to crash slapd via a specially crafted packet.
(CVE-2015-6908)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1509&L=scientific-linux-errata&F=&S=&P=21602
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d4496b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/30");
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


flag = 0;
if (rpm_check(release:"SL5", reference:"compat-openldap-2.3.43_2.2.29-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-debuginfo-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-devel-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-servers-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-servers-overlays-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openldap-servers-sql-2.3.43-29.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"openldap-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-debuginfo-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-devel-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-sql-2.4.40-6.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-clients-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-debuginfo-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-devel-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-servers-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.39-7.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-debuginfo / etc");
}
