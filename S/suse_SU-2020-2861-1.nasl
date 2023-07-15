#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2861-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143865);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");

  script_name(english:"SUSE SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2020:2861-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for java-1_7_0-openjdk fixes the following issues :

java-1_7_0-openjdk was updated to 2.6.23 (July 2020 CPU, bsc#1174157)

  - JDK-8028431, CVE-2020-14579: NullPointerException in

  - DerValue.equals(DerValue)

  - JDK-8028591, CVE-2020-14578: NegativeArraySizeException
    in

  - sun.security.util.DerInputStream.getUnalignedBitString()

  - JDK-8230613: Better ASCII conversions

  - JDK-8231800: Better listing of arrays

  - JDK-8232014: Expand DTD support

  - JDK-8233255: Better Swing Buttons

  - JDK-8234032: Improve basic calendar services

  - JDK-8234042: Better factory production of certificates

  - JDK-8234418: Better parsing with CertificateFactory

  - JDK-8234836: Improve serialization handling

  - JDK-8236191: Enhance OID processing

  - JDK-8237592, CVE-2020-14577: Enhance certificate
    verification

  - JDK-8238002, CVE-2020-14581: Better matrix operations

  - JDK-8238804: Enhance key handling process

  - JDK-8238842: AIOOBE in
    GIFImageReader.initializeStringTable

  - JDK-8238843: Enhanced font handing

  - JDK-8238920, CVE-2020-14583: Better Buffer support

  - JDK-8238925: Enhance WAV file playback

  - JDK-8240119, CVE-2020-14593: Less Affine Transformations

  - JDK-8240482: Improved WAV file playback

  - JDK-8241379: Update JCEKS support

  - JDK-8241522: Manifest improved jar headers redux

  - JDK-8242136, CVE-2020-14621: Better XML namespace
    handling

  - JDK-8040113: File not initialized in
    src/share/native/sun/awt/giflib/dgif_lib.c

  - JDK-8054446: Repeated offer and remove on
    ConcurrentLinkedQueue lead to an OutOfMemoryError

  - JDK-8077982: GIFLIB upgrade

  - JDK-8081315: 8077982 giflib upgrade breaks system giflib
    builds with earlier versions

  - JDK-8147087: Race when reusing PerRegionTable bitmaps
    may result in dropped remembered set entries

  - JDK-8151582: (ch) test
    java/nio/channels/AsyncCloseAndInterrupt.java failing
    due to 'Connection succeeded'

  - JDK-8155691: Update GIFlib library to the latest
    up-to-date

  - JDK-8181841: A TSA server returns timestamp with
    precision higher than milliseconds

  - JDK-8203190: SessionId.hashCode generates too many
    collisions

  - JDK-8217676: Upgrade libpng to 1.6.37

  - JDK-8220495: Update GIFlib library to the 5.1.8

  - JDK-8226892: ActionListeners on JRadioButtons don't get
    notified when selection is changed with arrow keys

  - JDK-8229899: Make java.io.File.isInvalid() less racy

  - JDK-8230597: Update GIFlib library to the 5.2.1

  - JDK-8230769: BufImg_SetupICM add
    ReleasePrimitiveArrayCritical call in early return

  - JDK-8243541: (tz) Upgrade time-zone data to tzdata2020a

  - JDK-8244548: JDK 8u: sun.misc.Version.jdkUpdateVersion()
    returns wrong result

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14577/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14578/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14579/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14581/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14583/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14593/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14621/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202861-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2724b1d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2020-2861=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-2861=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2020-2861=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-2861=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-2861=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2020-2861=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-2861=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-2861=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-2861=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2020-2861=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-2861=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-2861=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-2861=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-2861=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-2861=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-2861=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-debugsource-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-demo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-devel-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-headless-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-demo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-devel-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-headless-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-demo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-devel-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-headless-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-debugsource-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-demo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-devel-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-headless-1.7.0.271-43.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.271-43.41.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
