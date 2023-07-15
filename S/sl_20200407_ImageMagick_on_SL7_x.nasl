#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135797);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2017-1000476", "CVE-2017-11166", "CVE-2017-12805", "CVE-2017-12806", "CVE-2017-18251", "CVE-2017-18252", "CVE-2017-18254", "CVE-2017-18271", "CVE-2017-18273", "CVE-2018-10177", "CVE-2018-10804", "CVE-2018-10805", "CVE-2018-11656", "CVE-2018-12599", "CVE-2018-12600", "CVE-2018-13153", "CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437", "CVE-2018-15607", "CVE-2018-16328", "CVE-2018-16749", "CVE-2018-16750", "CVE-2018-18544", "CVE-2018-20467", "CVE-2018-8804", "CVE-2018-9133", "CVE-2019-10131", "CVE-2019-10650", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13133", "CVE-2019-13134", "CVE-2019-13135", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13454", "CVE-2019-14980", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-15141", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16712", "CVE-2019-16713", "CVE-2019-17540", "CVE-2019-17541", "CVE-2019-19948", "CVE-2019-19949", "CVE-2019-7175", "CVE-2019-7397", "CVE-2019-7398", "CVE-2019-9956");

  script_name(english:"Scientific Linux Security Update : ImageMagick on SL7.x x86_64 (20200407)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:"* ImageMagick: multiple security vulnerabilities"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=4745
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7d4e280"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autotrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autotrace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autotrace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:emacs-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:inkscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:inkscape-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:inkscape-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:inkscape-view");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-c++-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-devel-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-doc-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-perl-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"autotrace-0.31.1-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"autotrace-debuginfo-0.31.1-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"autotrace-devel-0.31.1-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"emacs-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"emacs-common-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"emacs-debuginfo-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", reference:"emacs-el-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", reference:"emacs-filesystem-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"emacs-filesystem-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"emacs-nox-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", reference:"emacs-terminal-24.3-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"inkscape-0.92.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"inkscape-debuginfo-0.92.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"inkscape-docs-0.92.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"inkscape-view-0.92.2-3.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
