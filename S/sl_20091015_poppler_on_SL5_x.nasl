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
  script_id(60680);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3603", "CVE-2009-3608", "CVE-2009-3609");

  script_name(english:"Scientific Linux Security Update : poppler on SL5.x i386/x86_64");
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
"CVE-2009-3608 xpdf/poppler: integer overflow in
ObjectStream::ObjectStream (oCERT-2009-016)

CVE-2009-3609 xpdf/poppler: ImageStream::ImageStream integer overflow

CVE-2009-3603 xpdf/poppler: SplashBitmap::SplashBitmap integer
overflow

Multiple integer overflow flaws were found in poppler. An attacker
could create a malicious PDF file that would cause applications that
use poppler (such as Evince) to crash or, potentially, execute
arbitrary code when opened. (CVE-2009-3603, CVE-2009-3608,
CVE-2009-3609)

This update also corrects a regression introduced in the previous
poppler security update, RHSA-2009:0480, that prevented poppler from
rendering certain PDF documents correctly. (BZ#528147)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=528147"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=1818
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1aa527e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected poppler, poppler-devel and / or poppler-utils
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"poppler-0.5.4-4.4.el5_4.11")) flag++;
if (rpm_check(release:"SL5", reference:"poppler-devel-0.5.4-4.4.el5_4.11")) flag++;
if (rpm_check(release:"SL5", reference:"poppler-utils-0.5.4-4.4.el5_4.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
