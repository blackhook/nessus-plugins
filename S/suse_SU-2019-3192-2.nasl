#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3192-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(138254);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/07");

  script_cve_id("CVE-2019-14491", "CVE-2019-14492", "CVE-2019-15939");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : opencv (SUSE-SU-2019:3192-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opencv fixes the following issues :

Security issues fixed :

CVE-2019-14491: Fixed an out of bounds read in the function
cv:predictOrdered<cv:HaarEvaluator>, leading to DOS (bsc#1144352).

CVE-2019-14492: Fixed an out of bounds read/write in the function
HaarEvaluator:OptFeature:calc, which leads to denial of service
(bsc#1144348).

CVE-2019-15939: Fixed a divide-by-zero error in
cv:HOGDescriptor:getDescriptorSize (bsc#1149742).

Non-security issue fixed :

Fixed an issue in opencv-devel that broke builds with 'No rule to make
target opencv_calib3d-NOTFOUND' (bsc#1154091).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14491/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14492/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15939/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193192-2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?302a3300"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP2 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP2-2020-1875=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2020-1875=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-1875=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14491");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:opencv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"opencv-debugsource-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"opencv-debugsource-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python2-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python2-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"opencv-debugsource-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python2-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python2-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"opencv-debugsource-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python2-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python2-opencv-debuginfo-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-opencv-3.3.1-6.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-opencv-debuginfo-3.3.1-6.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opencv");
}
