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
  script_id(71306);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1620", "CVE-2013-1739", "CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL5.x i386/x86_64 (20131205)");
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
"A flaw was found in the way NSS handled invalid handshake packets. A
remote attacker could use this flaw to cause a TLS/SSL client using
NSS to crash or, possibly, execute arbitrary code with the privileges
of the user running the application. (CVE-2013-5605)

It was found that the fix for CVE-2013-1620 released via
SLSA-2013:1135 introduced a regression causing NSS to read
uninitialized data when a decryption failure occurred. A remote
attacker could use this flaw to cause a TLS/SSL server using NSS to
crash. (CVE-2013-1739)

An integer overflow flaw was discovered in both NSS and NSPR's
implementation of certification parsing on 64-bit systems. A remote
attacker could use these flaws to cause an application using NSS or
NSPR to crash. (CVE-2013-1741, CVE-2013-5607)

It was discovered that NSS did not reject certificates with
incompatible key usage constraints when validating them while the
verifyLog feature was enabled. An application using the NSS
certificate validation API could accept an invalid certificate.
(CVE-2013-5606)

In addition, the nss package has been upgraded to upstream version
3.15.3, and the nspr package has been upgraded to upstream version
4.10.2. These updates provide a number of bug fixes and enhancements
over the previous versions.

This update also fixes the following bug :

  - The SLBA-2013:1318 update introduced a regression that
    prevented the use of certificates that have an MD5
    signature. This update fixes this regression and
    certificates that have an MD5 signature are once again
    supported. To prevent the use of certificates that have
    an MD5 signature, set the 'NSS_HASH_ALG_SUPPORT'
    environment variable to '-MD5'.

After installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=1793
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc19495c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"SL5", reference:"nspr-4.10.2-2.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-debuginfo-4.10.2-2.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.10.2-2.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.15.3-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.15.3-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.15.3-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.15.3-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.15.3-3.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
}
