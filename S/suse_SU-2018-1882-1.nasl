#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1882-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120029);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2017-11337", "CVE-2017-11338", "CVE-2017-11339", "CVE-2017-11340", "CVE-2017-11553", "CVE-2017-11591", "CVE-2017-11592", "CVE-2017-11683", "CVE-2017-12955", "CVE-2017-12956", "CVE-2017-12957", "CVE-2017-14859", "CVE-2017-14860", "CVE-2017-14862", "CVE-2017-14864");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : exiv2 (SUSE-SU-2018:1882-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for exiv2 to 0.26 fixes the following security issues :

  - CVE-2017-14864: Prevent invalid memory address
    dereference in Exiv2::getULong that could have caused a
    segmentation fault and application crash, which leads to
    denial of service (bsc#1060995).

  - CVE-2017-14862: Prevent invalid memory address
    dereference in Exiv2::DataValue::read that could have
    caused a segmentation fault and application crash, which
    leads to denial of service (bsc#1060996).

  - CVE-2017-14859: Prevent invalid memory address
    dereference in Exiv2::StringValueBase::read that could
    have caused a segmentation fault and application crash,
    which leads to denial of service (bsc#1061000).

  - CVE-2017-14860: Prevent heap-based buffer over-read in
    the Exiv2::Jp2Image::readMetadata function via a crafted
    input that could have lead to a denial of service attack
    (bsc#1061023).

  - CVE-2017-11337: Prevent invalid free in the
    Action::TaskFactory::cleanup function via a crafted
    input that could have lead to a remote denial of service
    attack (bsc#1048883).

  - CVE-2017-11338: Prevent infinite loop in the
    Exiv2::Image::printIFDStructure function via a crafted
    input that could have lead to a remote denial of service
    attack (bsc#1048883).

  - CVE-2017-11339: Prevent heap-based buffer overflow in
    the Image::printIFDStructure function via a crafted
    input that could have lead to a remote denial of service
    attack (bsc#1048883).

  - CVE-2017-11340: Prevent Segmentation fault in the
    XmpParser::terminate() function via a crafted input that
    could have lead to a remote denial of service attack
    (bsc#1048883).

  - CVE-2017-12955: Prevent heap-based buffer overflow. The
    vulnerability caused an out-of-bounds write in
    Exiv2::Image::printIFDStructure(), which may lead to
    remote denial of service or possibly unspecified other
    impact (bsc#1054593).

  - CVE-2017-12956: Preventn illegal address access in
    Exiv2::FileIo::path[abi:cxx11]() that could have lead to
    remote denial of service (bsc#1054592).

  - CVE-2017-12957: Prevent heap-based buffer over-read that
    was triggered in the Exiv2::Image::io function and could
    have lead to remote denial of service (bsc#1054590).

  - CVE-2017-11683: Prevent reachable assertion in the
    Internal::TiffReader::visitDirectory function that could
    have lead to a remote denial of service attack via
    crafted input (bsc#1051188).

  - CVE-2017-11591: Prevent Floating point exception in the
    Exiv2::ValueType function that could have lead to a
    remote denial of service attack via crafted input
    (bsc#1050257).

  - CVE-2017-11553: Prevent illegal address access in the
    extend_alias_table function via a crafted input could
    have lead to remote denial of service.

  - CVE-2017-11592: Prevent mismatched Memory Management
    Routines vulnerability in the Exiv2::FileIo::seek
    function that could have lead to a remote denial of
    service attack (heap memory corruption) via crafted
    input.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11337/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11338/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11339/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11553/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11591/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11592/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11683/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12955/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12956/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12957/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14859/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14860/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14862/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14864/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181882-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f1296bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-1280=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:exiv2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:exiv2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"exiv2-debuginfo-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"exiv2-debugsource-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libexiv2-26-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libexiv2-26-debuginfo-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libexiv2-devel-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"exiv2-debuginfo-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"exiv2-debugsource-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libexiv2-26-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libexiv2-26-debuginfo-0.26-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libexiv2-devel-0.26-6.3.1")) flag++;


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
