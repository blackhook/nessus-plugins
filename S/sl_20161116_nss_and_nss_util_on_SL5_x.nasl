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
  script_id(95052);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-2834", "CVE-2016-5285", "CVE-2016-8635");

  script_name(english:"Scientific Linux Security Update : nss and nss-util on SL5.x, SL6.x, SL7.x i386/x86_64 (20161116)");
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
"The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version:
nss (3.12.3), nss-util (3.12.3).

Security Fix(es) :

  - Multiple buffer handling flaws were found in the way NSS
    handled cryptographic data from the network. A remote
    attacker could use these flaws to crash an application
    using NSS or, possibly, execute arbitrary code with the
    permission of the user running the application.
    (CVE-2016-2834)

  - A NULL pointer dereference flaw was found in the way NSS
    handled invalid Diffie-Hellman keys. A remote client
    could use this flaw to crash a TLS/SSL server using NSS.
    (CVE-2016-5285)

  - It was found that Diffie Hellman Client key exchange
    handling in NSS was vulnerable to small subgroup
    confinement attack. An attacker could use this flaw to
    recover private keys by confining the client DH key to
    small subgroup of the desired group. (CVE-2016-8635)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1611&L=scientific-linux-errata&F=&S=&P=2517
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d7102ad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"nss-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.21.3-2.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"nss-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.21.3-1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.21.3-1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.21.3-1.el6_8")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.21.3-1.1.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.21.3-1.1.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.21.3-1.1.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
}
