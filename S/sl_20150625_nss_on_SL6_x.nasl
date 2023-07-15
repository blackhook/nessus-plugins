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
  script_id(84539);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Scientific Linux Security Update : nss on SL6.x, SL7.x i386/x86_64 (20150625) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"A flaw was found in the way the TLS protocol composes the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in NSS to
reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Future updates may raise this limit
to 1024 bits.

The nss and nss-util packages have been upgraded to upstream versions
3.19.1. The upgraded versions provide a number of bug fixes and
enhancements over the previous versions.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=14561
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5985bc5");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SL6", reference:"nss-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.19.1-1.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.19.1-1.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.19.1-1.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.19.1-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.19.1-1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.19.1-1.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
}
