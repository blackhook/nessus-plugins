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
  script_id(91039);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Scientific Linux Security Update : ImageMagick on SL6.x, SL7.x i386/x86_64 (20160509) (ImageTragick)");
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

  - It was discovered that ImageMagick did not properly
    sanitize certain input before passing it to the delegate
    functionality. A remote attacker could create a
    specially crafted image that, when processed by an
    application using ImageMagick or an unsuspecting user
    using the ImageMagick utilities, would lead to arbitrary
    execution of shell commands with the privileges of the
    user running the application. (CVE-2016-3714)

  - It was discovered that certain ImageMagick coders and
    pseudo-protocols did not properly prevent security
    sensitive operations when processing specially crafted
    images. A remote attacker could create a specially
    crafted image that, when processed by an application
    using ImageMagick or an unsuspecting user using the
    ImageMagick utilities, would allow the attacker to
    delete, move, or disclose the contents of arbitrary
    files. (CVE-2016-3715, CVE-2016-3716, CVE-2016-3717)

  - A server-side request forgery flaw was discovered in the
    way ImageMagick processed certain images. A remote
    attacker could exploit this flaw to mislead an
    application using ImageMagick or an unsuspecting user
    using the ImageMagick utilities into, for example,
    performing HTTP(S) requests or opening FTP sessions via
    specially crafted images. (CVE-2016-3718)

Note: This update contains an updated /etc/ImageMagick/policy.xml file
that disables the EPHEMERAL, HTTPS, HTTP, URL, FTP, MVG, MSL, TEXT,
and LABEL coders. If you experience any problems after the update, it
may be necessary to manually adjust the policy.xml file to match your
requirements. Please take additional precautions to ensure that your
applications using the ImageMagick library do not process malicious or
untrusted files before doing so."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1605&L=scientific-linux-errata&F=&S=&P=1966
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46d0d048"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"SL6", reference:"ImageMagick-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-c++-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-c++-devel-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-debuginfo-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-devel-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-doc-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-perl-6.7.2.7-4.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-c++-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-devel-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-doc-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ImageMagick-perl-6.7.8.9-13.el7_2")) flag++;


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
