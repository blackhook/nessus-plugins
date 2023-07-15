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
  script_id(96301);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-5653", "CVE-2016-7977", "CVE-2016-7979", "CVE-2016-8602");

  script_name(english:"Scientific Linux Security Update : ghostscript on SL6.x i386/x86_64 (20170104)");
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

  - It was found that the ghostscript functions getenv,
    filenameforall and .libfile did not honor the -dSAFER
    option, usually used when processing untrusted
    documents, leading to information disclosure. A
    specially crafted postscript document could read
    environment variable, list directory and retrieve file
    content respectively, from the target. (CVE-2013-5653,
    CVE-2016-7977)

  - It was found that the ghostscript function
    .initialize_dsc_parser did not validate its parameter
    before using it, allowing a type confusion flaw. A
    specially crafted postscript document could cause a
    crash code execution in the context of the gs process.
    (CVE-2016-7979)

  - It was found that ghostscript did not sufficiently check
    the validity of parameters given to the .sethalftone5
    function. A specially crafted postscript document could
    cause a crash, or execute arbitrary code in the context
    of the gs process. (CVE-2016-8602)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=808
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab100b4a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"ghostscript-8.70-21.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-debuginfo-8.70-21.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-devel-8.70-21.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-doc-8.70-21.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"ghostscript-gtk-8.70-21.el6_8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-debuginfo / ghostscript-devel / etc");
}
