#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0054-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105720);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13765", "CVE-2017-13766", "CVE-2017-13767", "CVE-2017-15191", "CVE-2017-15192", "CVE-2017-15193", "CVE-2017-17083", "CVE-2017-17084", "CVE-2017-17085", "CVE-2017-9617", "CVE-2017-9766");

  script_name(english:"SUSE SLES11 Security Update : wireshark (SUSE-SU-2018:0054-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark to version 2.2.11 fixes several issues.
These security issues were fixed :

  - CVE-2017-13767: The MSDP dissector could have gone into
    an infinite loop. This was addressed by adding length
    validation (bsc#1056248)

  - CVE-2017-13766: The Profinet I/O dissector could have
    crash with an out-of-bounds write. This was addressed by
    adding string validation (bsc#1056249)

  - CVE-2017-13765: The IrCOMM dissector had a buffer
    over-read and application crash. This was addressed by
    adding length validation (bsc#1056251)

  - CVE-2017-9766: PROFINET IO data with a high recursion
    depth allowed remote attackers to cause a denial of
    service (stack exhaustion) in the dissect_IODWriteReq
    function (bsc#1045341)

  - CVE-2017-9617: Deeply nested DAAP data may have cause
    stack exhaustion (uncontrolled recursion) in the
    dissect_daap_one_tag function in the DAAP dissector
    (bsc#1044417)

  - CVE-2017-15192: The BT ATT dissector could crash. This
    was addressed in epan/dissectors/packet-btatt.c by
    considering a case where not all of the BTATT packets
    have the same encapsulation level. (bsc#1062645)

  - CVE-2017-15193: The MBIM dissector could crash or
    exhaust system memory. This was addressed in
    epan/dissectors/packet-mbim.c by changing the
    memory-allocation approach. (bsc#1062645)

  - CVE-2017-15191: The DMP dissector could crash. This was
    addressed in epan/dissectors/packet-dmp.c by validating
    a string length. (bsc#1062645)

  - CVE-2017-17083: NetBIOS dissector could crash. This was
    addressed in epan/dissectors/packet-netbios.c by
    ensuring that write operations are bounded by the
    beginning of a buffer. (bsc#1070727)

  - CVE-2017-17084: IWARP_MPA dissector could crash. This
    was addressed in epan/dissectors/packet-iwarp-mpa.c by
    validating a ULPDU length. (bsc#1070727)

  - CVE-2017-17085: the CIP Safety dissector could crash.
    This was addressed in epan/dissectors/packet-cipsafety.c
    by validating the packet length. (bsc#1070727)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13765/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13766/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13767/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15191/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15192/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15193/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17083/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17084/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17085/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9617/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9766/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180054-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?895a93c8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-wireshark-13400=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-wireshark-13400=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-wireshark-13400=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:portaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");
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
if (rpm_check(release:"SLES11", sp:"4", reference:"libsmi-0.4.5-2.7.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwireshark8-2.2.11-40.14.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwiretap6-2.2.11-40.14.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwscodecs1-2.2.11-40.14.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwsutil7-2.2.11-40.14.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"portaudio-19-234.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-2.2.11-40.14.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-gtk-2.2.11-40.14.5")) flag++;


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
