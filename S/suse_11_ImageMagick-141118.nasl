#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80021);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562", "CVE-2014-8716");

  script_name(english:"SuSE 11.3 Security Update : Image Magick (SAT Patch Number 9976)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ImageMagick has been updated to fix four security issues :

  - Crafted jpeg file could have lead to a Denial of
    Service. (CVE-2014-8716)

  - Out-of-bounds memory access in resize code.
    (CVE-2014-8354)

  - Out-of-bounds memory access in PCX parser.
    (CVE-2014-8355)

  - Out-of-bounds memory error in DCM decode.
    (CVE-2014-8562)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8354.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8716.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9976.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libMagick++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libMagickCore1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libMagickWand1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"ImageMagick-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libMagick++1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libMagickCore1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libMagickWand1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"ImageMagick-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libMagick++1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libMagickCore1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libMagickWand1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libMagickCore1-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libMagickCore1-32bit-6.4.3.6-7.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-7.30.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
