#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135829);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2018-21009", "CVE-2019-10871", "CVE-2019-11459", "CVE-2019-12293", "CVE-2019-9959");

  script_name(english:"Scientific Linux Security Update : poppler and evince on SL7.x x86_64 (20200407)");
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
"* poppler: integer overflow in Parser::makeStream in Parser.cc *
poppler: heap-based buffer over-read in function
PSOutputDev::checkPageSlice in PSOutputDev.cc * poppler: heap-based
buffer over-read in JPXStream::init in JPEG2000Stream.cc * poppler:
integer overflow in JPXStream::init function leading to memory
consumption * evince: uninitialized memory use in function
tiff_document_render() and tiff_document_get_thumbnail()"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=14129
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?135f6233"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/05");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-browser-plugin-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-debuginfo-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-devel-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-dvi-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-libs-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-nautilus-3.28.2-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-cpp-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-cpp-devel-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-debuginfo-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-demos-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-devel-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-glib-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-glib-devel-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-qt-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-qt-devel-0.26.5-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-utils-0.26.5-42.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-browser-plugin / evince-debuginfo / evince-devel / etc");
}
