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
  script_id(74307);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");

  script_name(english:"Scientific Linux Security Update : libtasn1 on SL6.x i386/x86_64 (20140603)");
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
"It was discovered that the asn1_get_bit_der() function of the libtasn1
library incorrectly reported the length of ASN.1-encoded data.
Specially crafted ASN.1 input could cause an application using
libtasn1 to perform an out-of-bounds access operation, causing the
application to crash or, possibly, execute arbitrary code.
(CVE-2014-3468)

Multiple incorrect buffer boundary check issues were discovered in
libtasn1. Specially crafted ASN.1 input could cause an application
using libtasn1 to crash. (CVE-2014-3467)

Multiple NULL pointer dereference flaws were found in libtasn1's
asn1_read_value() function. Specially crafted ASN.1 input could cause
an application using libtasn1 to crash, if the application used the
aforementioned function in a certain way. (CVE-2014-3469)

For the update to take effect, all applications linked to the libtasn1
library must be restarted."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1406&L=scientific-linux-errata&T=0&P=549
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10bb42ba"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtasn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtasn1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtasn1-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/04");
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
if (rpm_check(release:"SL6", reference:"libtasn1-2.3-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libtasn1-debuginfo-2.3-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libtasn1-devel-2.3-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libtasn1-tools-2.3-6.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtasn1 / libtasn1-debuginfo / libtasn1-devel / libtasn1-tools");
}
