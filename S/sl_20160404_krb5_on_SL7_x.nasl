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
  script_id(90344);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631");

  script_name(english:"Scientific Linux Security Update : krb5 on SL7.x x86_64 (20160404)");
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

  - A memory leak flaw was found in the krb5_unparse_name()
    function of the MIT Kerberos kadmind service. An
    authenticated attacker could repeatedly send specially
    crafted requests to the server, which could cause the
    server to consume large amounts of memory resources,
    ultimately leading to a denial of service due to memory
    exhaustion. (CVE-2015-8631)

  - An out-of-bounds read flaw was found in the kadmind
    service of MIT Kerberos. An authenticated attacker could
    send a maliciously crafted message to force kadmind to
    read beyond the end of allocated memory, and write the
    memory contents to the KDC database if the attacker has
    write permission, leading to information disclosure.
    (CVE-2015-8629)

  - A NULL pointer dereference flaw was found in the
    procedure used by the MIT Kerberos kadmind service to
    store policies: the kadm5_create_principal_3() and
    kadm5_modify_principal() function did not ensure that a
    policy was given when KADM5_POLICY was set. An
    authenticated attacker with permissions to modify the
    database could use this flaw to add or modify a
    principal with a policy set to NULL, causing the kadmind
    service to crash. (CVE-2015-8630)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=76
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dbfa680"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/05");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-debuginfo-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-devel-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-libs-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-pkinit-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-ldap-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-workstation-1.13.2-12.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
}
