#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3610-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120153);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-17096", "CVE-2018-17097", "CVE-2018-17098");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : soundtouch (SUSE-SU-2018:3610-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for soundtouch fixes the following issues :

CVE-2018-17098: The WavFileBase class allowed remote attackers to
cause a denial of service (heap corruption from size inconsistency) or
possibly have unspecified other impact, as demonstrated by
SoundStretch. (bsc#1108632)

CVE-2018-17097: The WavFileBase class allowed remote attackers to
cause a denial of service (double free) or possibly have unspecified
other impact, as demonstrated by SoundStretch. (double free)
(bsc#1108631)

CVE-2018-17096: The BPMDetect class allowed remote attackers to cause
a denial of service (assertion failure and application exit), as
demonstrated by SoundStretch. (bsc#1108630)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17096/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17097/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17098/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183610-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e264e2c4"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2565=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-2565=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libSoundTouch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libSoundTouch0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:soundtouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:soundtouch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:soundtouch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:soundtouch-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"libSoundTouch0-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libSoundTouch0-debuginfo-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"soundtouch-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"soundtouch-debuginfo-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"soundtouch-debugsource-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"soundtouch-devel-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libSoundTouch0-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libSoundTouch0-debuginfo-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"soundtouch-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"soundtouch-debuginfo-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"soundtouch-debugsource-1.8.0-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"soundtouch-devel-1.8.0-3.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "soundtouch");
}
