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
  script_id(65606);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1016", "CVE-2013-1415");

  script_name(english:"Scientific Linux Security Update : krb5 on SL6.x i386/x86_64 (20130318)");
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
"When a client attempts to use PKINIT to obtain credentials from the
KDC, the client can specify, using an issuer and serial number, which
of the KDC's possibly-many certificates the client has in its
possession, as a hint to the KDC that it should use the corresponding
key to sign its response. If that specification was malformed, the KDC
could attempt to dereference a NULL pointer and crash. (CVE-2013-1415)

When a client attempts to use PKINIT to obtain credentials from the
KDC, the client will typically format its request to conform to the
specification published in RFC 4556. For interoperability reasons,
clients and servers also provide support for an older, draft version
of that specification. If a client formatted its request to conform to
this older version of the specification, with a non-default key
agreement option, it could cause the KDC to attempt to dereference a
NULL pointer and crash. (CVE-2012-1016)

After installing the updated packages, the krb5kdc daemon will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=5032
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e348fc42"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");
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
if (rpm_check(release:"SL6", reference:"krb5-debuginfo-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-devel-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-libs-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-pkinit-openssl-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-ldap-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-workstation-1.10.3-10.el6_4.1")) flag++;


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
