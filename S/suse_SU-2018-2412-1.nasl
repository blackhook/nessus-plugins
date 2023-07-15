#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2412-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112015);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11354", "CVE-2018-11355", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11358", "CVE-2018-11359", "CVE-2018-11360", "CVE-2018-11361", "CVE-2018-11362", "CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-14370");

  script_name(english:"SUSE SLES11 Security Update : wireshark (SUSE-SU-2018:2412-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark fixes the following issues: Security issues
fixed :

  - bsc#1094301: Wireshark security update to 2.6.1, 2.4.7,
    2.2.15

  - CVE-2018-14339: MMSE dissector infinite loop
    (wnpa-sec-2018-38, bsc#1101810)

  - CVE-2018-14341: DICOM dissector crash (wnpa-sec-2018-39,
    bsc#1101776)

  - CVE-2018-14343: ASN.1 BER dissector crash
    (wnpa-sec-2018-37, bsc#1101786)

  - CVE-2018-14344: ISMP dissector crash (wnpa-sec-2018-35,
    bsc#1101788)

  - CVE-2018-14340: Multiple dissectors could crash
    (wnpa-sec-2018-36, bsc#1101804)

  - CVE-2018-14342: BGP dissector large loop
    (wnpa-sec-2018-34, bsc#1101777)

  - CVE-2018-14370: IEEE 802.11 dissector crash
    (wnpa-sec-2018-43, bsc#1101802)

  - CVE-2018-14369: HTTP2 dissector crash (wnpa-sec-2018-41,
    bsc#1101800)

  - CVE-2018-14367: CoAP dissector crash (wnpa-sec-2018-42,
    bsc#1101791)

  - CVE-2018-14368: Bazaar dissector infinite loop
    (wnpa-sec-2018-40, bsc#1101794)

  - CVE-2018-11355: Fix RTCP dissector crash (bsc#1094301).

  - CVE-2018-11362: Fix LDSS dissector crash (bsc#1094301).

  - CVE-2018-11361: Fix IEEE 802.11 dissector crash
    (bsc#1094301).

  - CVE-2018-11360: Fix GSM A DTAP dissector crash
    (bsc#1094301).

  - CVE-2018-11358: Fix Q.931 dissector crash (bsc#1094301).

  - CVE-2018-11359: Fix multiple dissectors crashs
    (bsc#1094301).

  - CVE-2018-11356: Fix DNS dissector crash (bsc#1094301).

  - CVE-2018-11357: Fix multiple dissectors that could
    consume excessive memory (bsc#1094301).

  - CVE-2018-11354: Fix IEEE 1905.1a dissector crash
    (bsc#1094301).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11354/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11355/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11356/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11357/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11358/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11359/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11360/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11361/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11362/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14339/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14341/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14342/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14343/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14344/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14367/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14368/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14369/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14370/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182412-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b308d13d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-wireshark-13740=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-wireshark-13740=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-wireshark-13740=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwireshark8-2.2.16-40.28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwiretap6-2.2.16-40.28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwscodecs1-2.2.16-40.28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwsutil7-2.2.16-40.28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-2.2.16-40.28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-gtk-2.2.16-40.28.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
