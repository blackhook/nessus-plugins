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
  script_id(102677);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-1000061");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Scientific Linux Security Update : xmlsec1 on SL7.x x86_64 (20170821)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - It was discovered xmlsec1's use of libxml2 inadvertently
    enabled external entity expansion (XXE) along with
    validation. An attacker could craft an XML file that
    would cause xmlsec1 to try and read local files or
    HTTP/FTP URLs, leading to information disclosure or
    denial of service. (CVE-2017-1000061)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=1471
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a984c3b");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-gcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-debuginfo-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-gcrypt-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-gcrypt-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-gnutls-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-gnutls-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-nss-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-nss-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-openssl-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xmlsec1-openssl-devel-1.2.20-7.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xmlsec1 / xmlsec1-debuginfo / xmlsec1-devel / xmlsec1-gcrypt / etc");
}
