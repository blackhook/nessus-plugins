#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0921-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(135228);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-1000126", "CVE-2017-9239", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-17229", "CVE-2018-17230", "CVE-2018-17282", "CVE-2018-19108", "CVE-2018-19607", "CVE-2018-9305", "CVE-2019-13114");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : exiv2 (SUSE-SU-2020:0921-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for exiv2 fixes the following issues :

exiv2 was updated to latest 0.26 branch, fixing bugs and security
issues :

CVE-2017-1000126: Fixed an out of bounds read in webp parser
(bsc#1068873).

CVE-2017-9239: Fixed a segmentation fault in
TiffImageEntry::doWriteImage function (bsc#1040973).

CVE-2018-12264: Fixed an integer overflow in LoaderTiff::getData()
which might have led to an out-of-bounds read (bsc#1097600).

CVE-2018-12265: Fixed integer overflows in LoaderExifJpeg which could
have led to memory corruption (bsc#1097599).

CVE-2018-17229: Fixed a heap-based buffer overflow in Exiv2::d2Data
via a crafted image (bsc#1109175).

CVE-2018-17230: Fixed a heap-based buffer overflow in Exiv2::d2Data
via a crafted image (bsc#1109176).

CVE-2018-17282: Fixed a NULL pointer dereference in
Exiv2::DataValue::copy (bsc#1109299).

CVE-2018-19108: Fixed an integer overflow in
Exiv2::PsdImage::readMetadata which could have led to infinite loop
(bsc#1115364).

CVE-2018-19607: Fixed a NULL pointer dereference in Exiv2::isoSpeed
which might have led to denial of service (bsc#1117513).

CVE-2018-9305: Fixed an out of bounds read in IptcData::printStructure
which might have led to to information leak or denial of service
(bsc#1088424).

CVE-2019-13114: Fixed a NULL pointer dereference which might have led
to denial of service via a crafted response of an malicious http
server (bsc#1142684).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000126/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9239/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12264/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12265/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17229/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17230/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17282/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19108/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19607/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-9305/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13114/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200921-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e70efef6"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-921=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-921=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:exiv2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:exiv2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-26-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libexiv2-26-32bit-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libexiv2-26-32bit-debuginfo-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"exiv2-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"exiv2-debuginfo-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"exiv2-debugsource-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libexiv2-26-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libexiv2-26-debuginfo-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libexiv2-devel-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libexiv2-doc-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libexiv2-26-32bit-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libexiv2-26-32bit-debuginfo-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"exiv2-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"exiv2-debuginfo-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"exiv2-debugsource-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libexiv2-26-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libexiv2-26-debuginfo-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libexiv2-devel-0.26-6.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libexiv2-doc-0.26-6.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2");
}
