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
  script_id(87839);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3223", "CVE-2015-5330");

  script_name(english:"Scientific Linux Security Update : libldb on SL6.x, SL7.x i386/x86_64 (20160107)");
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
"A denial of service flaw was found in the ldb_wildcard_compare()
function of libldb. A remote attacker could send a specially crafted
packet that, when processed by an application using libldb (for
example the AD LDAP server in Samba), would cause that application to
consume an excessive amount of memory and crash. (CVE-2015-3223)

A memory-read flaw was found in the way the libldb library processed
LDB DN records with a null byte. An authenticated, remote attacker
could use this flaw to read heap-memory pages from the server.
(CVE-2015-5330)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1601&L=scientific-linux-errata&F=&S=&P=2279
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d3ac5a5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pyldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pyldb-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
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
if (rpm_check(release:"SL6", reference:"ldb-tools-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-debuginfo-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-devel-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pyldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pyldb-devel-1.1.13-3.el6_7.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ldb-tools-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-debuginfo-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-devel-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pyldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pyldb-devel-1.1.20-1.el7_2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb-tools / libldb / libldb-debuginfo / libldb-devel / pyldb / etc");
}
