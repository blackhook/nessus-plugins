#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1442-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100539);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-6354", "CVE-2016-7175", "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178", "CVE-2016-7179", "CVE-2016-7180", "CVE-2016-9373", "CVE-2016-9374", "CVE-2016-9375", "CVE-2016-9376", "CVE-2017-5596", "CVE-2017-5597", "CVE-2017-6014", "CVE-2017-7700", "CVE-2017-7701", "CVE-2017-7702", "CVE-2017-7703", "CVE-2017-7704", "CVE-2017-7705", "CVE-2017-7745", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-7748");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : wireshark (SUSE-SU-2017:1442-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to version 2.2.6, which brings several new
features, enhancements and bug fixes. Thses security issues were 
fixed :

  - CVE-2017-7700: In Wireshark the NetScaler file parser
    could go into an infinite loop, triggered by a malformed
    capture file. This was addressed in wiretap/netscaler.c
    by ensuring a nonzero record size (bsc#1033936)

  - CVE-2017-7701: In Wireshark the BGP dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-bgp.c by using a different
    integer data type (bsc#1033937)

  - CVE-2017-7702: In Wireshark the WBXML dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-wbxml.c by adding length
    validation (bsc#1033938)

  - CVE-2017-7703: In Wireshark the IMAP dissector could
    crash, triggered by packet injection or a malformed
    capture file. This was addressed in
    epan/dissectors/packet-imap.c by calculating a line's
    end correctly (bsc#1033939)

  - CVE-2017-7704: In Wireshark the DOF dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-dof.c by using a different
    integer data type and adjusting a return value
    (bsc#1033940)

  - CVE-2017-7705: In Wireshark the RPC over RDMA dissector
    could go into an infinite loop, triggered by packet
    injection or a malformed capture file. This was
    addressed in epan/dissectors/packet-rpcrdma.c by
    correctly checking for going beyond the maximum offset
    (bsc#1033941)

  - CVE-2017-7745: In Wireshark the SIGCOMP dissector could
    go into an infinite loop, triggered by packet injection
    or a malformed capture file. This was addressed in
    epan/dissectors/packet-sigcomp.c by correcting a
    memory-size check (bsc#1033942)

  - CVE-2017-7746: In Wireshark the SLSK dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-slsk.c by adding checks for the
    remaining length (bsc#1033943)

  - CVE-2017-7747: In Wireshark the PacketBB dissector could
    crash, triggered by packet injection or a malformed
    capture file. This was addressed in
    epan/dissectors/packet-packetbb.c by restricting
    additions to the protocol tree (bsc#1033944)

  - CVE-2017-7748: In Wireshark the WSP dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-wsp.c by adding a length check
    (bsc#1033945)

  - CVE-2017-6014: In Wireshark a crafted or malformed
    STANAG 4607 capture file will cause an infinite loop and
    memory exhaustion. If the packet size field in a packet
    header is null, the offset to read from will not
    advance, causing continuous attempts to read the same
    zero length packet. This will quickly exhaust all system
    memory (bsc#1025913)

  - CVE-2017-5596: In Wireshark the ASTERIX dissector could
    go into an infinite loop, triggered by packet injection
    or a malformed capture file. This was addressed in
    epan/dissectors/packet-asterix.c by changing a data type
    to avoid an integer overflow (bsc#1021739)

  - CVE-2017-5597: In Wireshark the DHCPv6 dissector could
    go into a large loop, triggered by packet injection or a
    malformed capture file. This was addressed in
    epan/dissectors/packet-dhcpv6.c by changing a data type
    to avoid an integer overflow (bsc#1021739)

  - CVE-2016-9376: In Wireshark the OpenFlow dissector could
    crash with memory exhaustion, triggered by network
    traffic or a capture file. This was addressed in
    epan/dissectors/packet-openflow_v5.c by ensuring that
    certain length values were sufficiently large
    (bsc#1010735)

  - CVE-2016-9375: In Wireshark the DTN dissector could go
    into an infinite loop, triggered by network traffic or a
    capture file. This was addressed in
    epan/dissectors/packet-dtn.c by checking whether SDNV
    evaluation was successful (bsc#1010740)

  - CVE-2016-9374: In Wireshark the AllJoyn dissector could
    crash with a buffer over-read, triggered by network
    traffic or a capture file. This was addressed in
    epan/dissectors/packet-alljoyn.c by ensuring that a
    length variable properly tracked the state of a
    signature variable (bsc#1010752)

  - CVE-2016-9373: In Wireshark the DCERPC dissector could
    crash with a use-after-free, triggered by network
    traffic or a capture file. This was addressed in
    epan/dissectors/packet-dcerpc-nt.c and
    epan/dissectors/packet-dcerpc-spoolss.c by using the
    wmem file scope for private strings (bsc#1010754)

  - CVE-2016-7180: epan/dissectors/packet-ipmi-trace.c in
    the IPMI trace dissector in Wireshark did not properly
    consider whether a string is constant, which allowed
    remote attackers to cause a denial of service
    (use-after-free and application crash) via a crafted
    packet (bsc#998800)

  - CVE-2016-7179: Stack-based buffer overflow in
    epan/dissectors/packet-catapult-dct2000.c in the
    Catapult DCT2000 dissector in Wireshark allowed remote
    attackers to cause a denial of service (application
    crash) via a crafted packet (bsc#998963)

  - CVE-2016-7178: epan/dissectors/packet-umts_fp.c in the
    UMTS FP dissector in Wireshark did not ensure that
    memory is allocated for certain data structures, which
    allowed remote attackers to cause a denial of service
    (invalid write access and application crash) via a
    crafted packet (bsc#998964)

  - CVE-2016-7177: epan/dissectors/packet-catapult-dct2000.c
    in the Catapult DCT2000 dissector in Wireshark did not
    restrict the number of channels, which allowed remote
    attackers to cause a denial of service (buffer over-read
    and application crash) via a crafted packet (bsc#998763)

  - CVE-2016-7176: epan/dissectors/packet-h225.c in the
    H.225 dissector in Wireshark called snprintf with one of
    its input buffers as the output buffer, which allowed
    remote attackers to cause a denial of service (copy
    overlap and application crash) via a crafted packet
    (bsc#998762)

  - CVE-2016-7175: epan/dissectors/packet-qnet6.c in the
    QNX6 QNET dissector in Wireshark mishandled MAC address
    data, which allowed remote attackers to cause a denial
    of service (out-of-bounds read and application crash)
    via a crafted packet (bsc#998761)

  - CVE-2016-6354: Heap-based buffer overflow in the
    yy_get_next_buffer function in Flex might have allowed
    context-dependent attackers to cause a denial of service
    or possibly execute arbitrary code via vectors involving
    num_to_read (bsc#990856).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1002981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1026507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6354/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7175/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7176/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7177/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7178/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7179/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7180/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9373/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9374/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9375/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9376/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5596/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5597/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6014/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7700/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7701/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7702/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7703/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7704/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7705/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7746/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7747/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7748/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171442-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92b0341b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-883=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-883=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-883=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-883=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-883=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-883=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-883=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwireshark8-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwireshark8-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwiretap6-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwiretap6-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwscodecs1-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwscodecs1-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwsutil7-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwsutil7-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-debugsource-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-gtk-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-gtk-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwireshark8-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwireshark8-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwiretap6-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwiretap6-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwscodecs1-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwsutil7-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwsutil7-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"wireshark-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"wireshark-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"wireshark-debugsource-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"wireshark-gtk-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwireshark8-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwireshark8-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwiretap6-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwiretap6-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwscodecs1-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwsutil7-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwsutil7-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-debugsource-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-gtk-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwireshark8-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwireshark8-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwiretap6-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwiretap6-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwscodecs1-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwsutil7-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libwsutil7-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-debuginfo-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-debugsource-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-gtk-2.2.6-44.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.2.6-44.3")) flag++;


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
