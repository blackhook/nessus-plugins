#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1277-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148874);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/19");

  script_cve_id("CVE-2021-20309", "CVE-2021-20311", "CVE-2021-20312", "CVE-2021-20313");

  script_name(english:"SUSE SLES12 Security Update : ImageMagick (SUSE-SU-2021:1277-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ImageMagick fixes the following issues :

CVE-2021-20309: Division by zero in WaveImage() of
MagickCore/visual-effects. (bsc#1184624)

CVE-2021-20311: Division by zero in sRGBTransformImage() in
MagickCore/colorspace.c (bsc#1184626)

CVE-2021-20312: Integer overflow in WriteTHUMBNAILImage of
coders/thumbnail.c (bsc#1184627)

CVE-2021-20313: Cipher leak when the calculating signatures in
TransformSignatureof MagickCore/signature.c (bsc#1184628)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1184624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1184626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1184627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1184628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20311/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20312/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20313/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211277-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21b8ce3b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP5 :

zypper in -t patch SUSE-SLE-WE-12-SP5-2021-1277=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-1277=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-1277=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20313");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-6-SUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-6-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", reference:"ImageMagick-config-6-SUSE-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ImageMagick-config-6-upstream-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ImageMagick-debuginfo-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ImageMagick-debugsource-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.165.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.165.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
