#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(106338);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2017-15134");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL7.x x86_64 (20180125)");
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

  - A stack-based buffer overflow flaw was found in the way
    389-ds-base handled certain LDAP search filters. A
    remote, unauthenticated attacker could potentially use
    this flaw to make ns-slapd crash via a specially crafted
    LDAP request, thus resulting in denial of service.
    (CVE-2017-15134)

Bug Fix(es) :

  - Previously, when a connection received a high operation
    rate, Directory Server stopped to poll the connection in
    certain situations. As a consequence, new requests on
    the connection were not detected and processed. With
    this update, Directory Server correctly decides whether
    a connection has to be polled. As a result, connections
    with a high request rate no longer remain unprocessed.

  - Previously, if Directory Server was stopped during an
    operation which created additional changes in the memory
    changelog, the Replication Update Vector (RUV) in the
    changelog was higher than the RUV in the database. As a
    consequence, Directory Server recreated the changelog
    when the server started. With this update, the server
    now writes the highest RUV to the changelog only if
    there is the highest Change Sequence Number (CSN)
    present in it. As a result, the database and the
    changelog RUV are consistent and the server does not
    need recreating the changelog at start up.

  - Due to a bug, using a large number of Class of Service
    (CoS) templates in Directory Server increased the
    virtual attribute processing time. This update improves
    the structure of the CoS storage. As a result, using a
    large number of CoS templates no longer increases the
    virtual attribute processing time."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1801&L=scientific-linux-errata&F=&S=&P=8825
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc9178d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.6.1-26.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
