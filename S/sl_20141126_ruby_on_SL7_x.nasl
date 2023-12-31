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
  script_id(79658);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090");

  script_name(english:"Scientific Linux Security Update : ruby on SL7.x x86_64 (20141126)");
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
"Multiple denial of service flaws were found in the way the Ruby REXML
XML parser performed expansion of parameter entities. A specially
crafted XML document could cause REXML to use an excessive amount of
CPU and memory. (CVE-2014-8080, CVE-2014-8090)

A stack-based buffer overflow was found in the implementation of the
Ruby Array pack() method. When performing base64 encoding, a single
byte could be written past the end of the buffer, possibly causing
Ruby to crash. (CVE-2014-4975)

All running instances of Ruby need to be restarted for this update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e191d8f6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-debuginfo-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-devel-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"ruby-doc-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"ruby-irb-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-libs-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-json-1.7.7-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-minitest-4.3.2-22.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-rake-0.9.6-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-rdoc-4.0.0-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rubygems-2.0.14-22.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rubygems-devel-2.0.14-22.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-doc / ruby-irb / etc");
}
