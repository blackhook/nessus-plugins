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
  script_id(69279);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0791", "CVE-2013-1620");

  script_name(english:"Scientific Linux Security Update : nss, nss-util, nss-softokn, and nspr on SL6.x i386/x86_64 (20130807)");
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
"It was discovered that NSS leaked timing information when decrypting
TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL or
DTLS server as a padding oracle. (CVE-2013-1620)

An out-of-bounds memory read flaw was found in the way NSS decoded
certain certificates. If an application using NSS decoded a malformed
certificate, it could cause the application to crash. (CVE-2013-0791)

This update also fixes the following bugs :

  - The SLBA-2013:0445 update (which upgraded NSS to version
    3.14) prevented the use of certificates that have an MD5
    signature. This caused problems in certain environments.
    With this update, certificates that have an MD5
    signature are once again allowed. To prevent the use of
    certificates that have an MD5 signature, set the
    'NSS_HASH_ALG_SUPPORT' environment variable to '-MD5'.

  - Previously, the sechash.h header file was missing,
    preventing certain source RPMs (such as firefox and
    xulrunner) from building.

  - A memory leak in the nssutil_ReadSecmodDB() function has
    been fixed.

In addition, the nss package has been upgraded to upstream version
3.14.3, the nss-util package has been upgraded to upstream version
3.14.3, the nss-softokn package has been upgraded to upstream version
3.14.3, and the nspr package has been upgraded to upstream version
4.9.5. These updates provide a number of bug fixes and enhancements
over the previous versions.

After installing this update, applications using NSS, NSPR, nss-util,
or nss-softokn must be restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1308&L=scientific-linux-errata&T=0&P=705
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8788bae4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/09");
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
if (rpm_check(release:"SL6", reference:"nspr-4.9.5-2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.9.5-2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.9.5-2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-debuginfo-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-devel-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-freebl-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-freebl-devel-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.14.3-3.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
}
