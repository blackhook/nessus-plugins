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
  script_id(61407);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1013", "CVE-2012-1015");

  script_name(english:"Scientific Linux Security Update : krb5 on SL6.x i386/x86_64 (20120731)");
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
"Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

An uninitialized pointer use flaw was found in the way the MIT
Kerberos KDC handled initial authentication requests (AS-REQ). A
remote, unauthenticated attacker could use this flaw to crash the KDC
via a specially crafted AS-REQ request. (CVE-2012-1015)

A NULL pointer dereference flaw was found in the MIT Kerberos
administration daemon, kadmind. A Kerberos administrator who has the
'create' privilege could use this flaw to crash kadmind.
(CVE-2012-1013)

All krb5 users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the
updated packages, the krb5kdc and kadmind daemons will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=209
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b5ec1d4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"krb5-debuginfo-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-devel-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-libs-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-pkinit-openssl-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-ldap-1.9-33.el6_3.2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-workstation-1.9-33.el6_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit-openssl / etc");
}
