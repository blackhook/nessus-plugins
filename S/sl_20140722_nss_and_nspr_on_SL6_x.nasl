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
  script_id(76702);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1544", "CVE-2014-1545");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL6.x i386/x86_64 (20140722)");
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
"A race condition was found in the way NSS verified certain
certificates. A remote attacker could use this flaw to crash an
application using NSS or, possibly, execute arbitrary code with the
privileges of the user running that application. (CVE-2014-1544)

A flaw was found in the way TLS False Start was implemented in NSS. An
attacker could use this flaw to potentially return unencrypted
information from the server. (CVE-2013-1740)

A race condition was found in the way NSS implemented session ticket
handling as specified by RFC 5077. An attacker could use this flaw to
crash an application using NSS or, in rare cases, execute arbitrary
code with the privileges of the user running that application.
(CVE-2014-1490)

It was found that NSS accepted weak Diffie-Hellman Key exchange (DHKE)
parameters. This could possibly lead to weak encryption being used in
communication between the client and the server. (CVE-2014-1491)

An out-of-bounds write flaw was found in NSPR. A remote attacker could
potentially use this flaw to crash an application using NSPR or,
possibly, execute arbitrary code with the privileges of the user
running that application. This NSPR flaw was not exposed to web
content in any shipped version of Firefox. (CVE-2014-1545)

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

In addition, the nss package has been upgraded to upstream version
3.16.1, and the nspr package has been upgraded to upstream version
4.10.6. These updated packages provide a number of bug fixes and
enhancements over the previous versions.

After installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1407&L=scientific-linux-errata&T=0&P=1484
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?348ff2de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nspr-devel");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"nspr-4.10.6-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.10.6-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.10.6-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.16.1-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.16.1-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.16.1-1.el6_5")) flag++;


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
