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
  script_id(65094);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1005", "CVE-2012-4481", "CVE-2013-1821");

  script_name(english:"Scientific Linux Security Update : ruby on SL6.x i386/x86_64 (20130307)");
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
"It was discovered that Ruby's REXML library did not properly restrict
XML entity expansion. An attacker could use this flaw to cause a
denial of service by tricking a Ruby application using REXML to read
text nodes from specially crafted XML content, which will result in
REXML consuming large amounts of system memory. (CVE-2013-1821)

It was found that the SLSA-2011:0910 update did not correctly fix the
CVE-2011-1005 issue, a flaw in the method for translating an exception
message into a string in the Exception class. A remote attacker could
use this flaw to bypass safe level 4 restrictions, allowing untrusted
(tainted) code to modify arbitrary, trusted (untainted) strings, which
safe level 4 restrictions would otherwise prevent. (CVE-2012-4481)

The CVE-2012-4481 issue was discovered by Vit Ondruch of Red Hat."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=2967
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?620a24f5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");
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
if (rpm_check(release:"SL6", reference:"ruby-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-debuginfo-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-devel-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-docs-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-irb-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-libs-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-rdoc-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-ri-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-static-1.8.7.352-10.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-tcltk-1.8.7.352-10.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-docs / ruby-irb / etc");
}
