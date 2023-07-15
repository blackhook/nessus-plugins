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
  script_id(66708);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1619", "CVE-2013-2116");

  script_name(english:"Scientific Linux Security Update : gnutls on SL5.x, SL6.x i386/srpm/x86_64 (20130530)");
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
"It was discovered that the fix for the CVE-2013-1619 issue released
via SLSA-2013:0588 introduced a regression in the way GnuTLS decrypted
TLS/SSL encrypted records when CBC-mode cipher suites were used. A
remote attacker could possibly use this flaw to crash a server or
client application that uses GnuTLS. (CVE-2013-2116)

For the update to take effect, all applications linked to the GnuTLS
library must be restarted."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1305&L=scientific-linux-errata&T=0&P=2550
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10b27527"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");
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
if (rpm_check(release:"SL5", reference:"gnutls-1.4.1-10.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-debuginfo-1.4.1-10.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-debuginfo-1.4.1-10.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-devel-1.4.1-10.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-utils-1.4.1-10.el5_9.2")) flag++;

if (rpm_check(release:"SL6", reference:"gnutls-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-debuginfo-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-debuginfo-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-devel-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-guile-2.8.5-10.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-utils-2.8.5-10.el6_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-devel / gnutls-guile / etc");
}
