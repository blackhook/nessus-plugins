#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0693-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134625);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-11354", "CVE-2018-11355", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11358", "CVE-2018-11359", "CVE-2018-11360", "CVE-2018-11361", "CVE-2018-11362", "CVE-2018-12086", "CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-14370", "CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058", "CVE-2018-18225", "CVE-2018-18226", "CVE-2018-18227", "CVE-2018-19622", "CVE-2018-19623", "CVE-2018-19624", "CVE-2018-19625", "CVE-2018-19626", "CVE-2018-19627", "CVE-2018-19628", "CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10897", "CVE-2019-10898", "CVE-2019-10899", "CVE-2019-10900", "CVE-2019-10901", "CVE-2019-10902", "CVE-2019-10903", "CVE-2019-13619", "CVE-2019-16319", "CVE-2019-19553", "CVE-2019-5716", "CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719", "CVE-2019-5721", "CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214", "CVE-2020-7044", "CVE-2020-9428", "CVE-2020-9429", "CVE-2020-9430", "CVE-2020-9431");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : wireshark (SUSE-SU-2020:0693-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for wireshark and libmaxminddb fixes the following 
issues :

Update wireshark to new major version 3.2.2 and introduce libmaxminddb
for GeoIP support (bsc#1156288).

New features include :

Added support for 111 new protocols, including WireGuard, LoRaWAN, TPM
2.0, 802.11ax and QUIC

Improved support for existing protocols, like HTTP/2

Improved analytics and usability functionalities

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093733"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957624"
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
    value:"https://www.suse.com/security/cve/CVE-2018-12086/"
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16056/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16057/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16058/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18225/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18226/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18227/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19622/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19623/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19624/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19625/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19626/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19627/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19628/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10894/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10895/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10896/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10897/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10898/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10899/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10900/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10901/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10902/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10903/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13619/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-16319/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19553/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5716/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5717/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5718/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5719/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5721/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9208/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9209/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9214/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-7044/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-9428/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-9429/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-9430/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-9431/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200693-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a67d1f5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15:zypper in -t patch
SUSE-SLE-Product-SLES_SAP-15-2020-693=1

SUSE Linux Enterprise Server 15-LTSS:zypper in -t patch
SUSE-SLE-Product-SLES-15-2020-693=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-693=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-693=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-693=1

SUSE Linux Enterprise High Performance Computing 15-LTSS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-693=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-693=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmaxminddb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmaxminddb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmaxminddb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmaxminddb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmaxminddb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspandsp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspandsp2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspandsp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mmdblookup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spandsp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spandsp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmaxminddb0-32bit-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libmaxminddb0-32bit-debuginfo-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libspandsp2-32bit-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libspandsp2-32bit-debuginfo-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmaxminddb-debugsource-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmaxminddb-devel-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmaxminddb0-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libmaxminddb0-debuginfo-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libspandsp2-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libspandsp2-debuginfo-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwireshark13-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwireshark13-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwiretap10-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwiretap10-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwsutil11-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwsutil11-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"mmdblookup-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"spandsp-debugsource-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"spandsp-devel-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wireshark-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wireshark-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wireshark-debugsource-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wireshark-devel-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wireshark-ui-qt-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"wireshark-ui-qt-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmaxminddb-debugsource-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmaxminddb-devel-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmaxminddb0-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libmaxminddb0-debuginfo-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libspandsp2-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libspandsp2-debuginfo-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwireshark13-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwireshark13-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwiretap10-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwiretap10-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwsutil11-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwsutil11-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"mmdblookup-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"wireshark-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"wireshark-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"wireshark-debugsource-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmaxminddb0-32bit-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libmaxminddb0-32bit-debuginfo-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libspandsp2-32bit-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libspandsp2-32bit-debuginfo-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmaxminddb-debugsource-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmaxminddb-devel-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmaxminddb0-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libmaxminddb0-debuginfo-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libspandsp2-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libspandsp2-debuginfo-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwireshark13-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwireshark13-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwiretap10-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwiretap10-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwsutil11-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwsutil11-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"mmdblookup-1.4.2-1.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"spandsp-debugsource-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"spandsp-devel-0.0.6-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"wireshark-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"wireshark-debuginfo-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"wireshark-debugsource-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"wireshark-devel-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"wireshark-ui-qt-3.2.2-3.35.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"wireshark-ui-qt-debuginfo-3.2.2-3.35.2")) flag++;


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
