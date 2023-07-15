#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131579);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-8712",
    "CVE-2015-8713",
    "CVE-2015-8714",
    "CVE-2015-8716",
    "CVE-2015-8717",
    "CVE-2015-8718",
    "CVE-2015-8719",
    "CVE-2015-8721",
    "CVE-2015-8723",
    "CVE-2015-8729",
    "CVE-2015-8731",
    "CVE-2016-2523",
    "CVE-2016-2530",
    "CVE-2016-2531",
    "CVE-2016-2532",
    "CVE-2016-4006",
    "CVE-2016-4077",
    "CVE-2016-4081",
    "CVE-2016-4085",
    "CVE-2016-5350",
    "CVE-2016-5353",
    "CVE-2016-5359",
    "CVE-2016-6505",
    "CVE-2016-6507",
    "CVE-2016-6508",
    "CVE-2016-6510",
    "CVE-2016-7177",
    "CVE-2016-7179",
    "CVE-2016-7958",
    "CVE-2016-9375",
    "CVE-2017-13765",
    "CVE-2017-17083",
    "CVE-2017-7703",
    "CVE-2017-9345",
    "CVE-2017-9347",
    "CVE-2017-9349",
    "CVE-2017-9352",
    "CVE-2018-14340",
    "CVE-2018-14341",
    "CVE-2018-16057",
    "CVE-2018-19622",
    "CVE-2018-5336",
    "CVE-2018-7418"
  );

  script_name(english:"EulerOS 2.0 SP2 : wireshark (EulerOS-SA-2019-2425)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the wireshark packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Wireshark is a network traffic analyzer for Unix-ish
    operating systems.This package lays base for libpcap, a
    packet capture and filtering library, contains
    command-line utilities, contains plugins and
    documentation for wireshark. A graphical user interface
    is packaged separately to GTK+ package.Security
    Fix(es):In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7,
    and 2.2.0 to 2.2.15, dissectors that support zlib
    decompression could crash. This was addressed in
    epan/tvbuff_zlib.c by rejecting negative lengths to
    avoid a buffer over-read.(CVE-2018-14340)In Wireshark
    2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15,
    the DICOM dissector could go into a large or infinite
    loop. This was addressed in
    epan/dissectors/packet-dcm.c by preventing an offset
    overflow.(CVE-2018-14341)In Wireshark 2.4.0 to 2.4.3
    and 2.2.0 to 2.2.11, the JSON, XML, NTP, XMPP, and GDB
    dissectors could crash. This was addressed in
    epan/tvbparse.c by limiting the recursion
    depth.(CVE-2018-5336)In Wireshark 2.2.0 to 2.2.12 and
    2.4.0 to 2.4.4, the SIGCOMP dissector could crash. This
    was addressed in epan/dissectors/packet-sigcomp.c by
    correcting the extraction of the length
    value.(CVE-2018-7418)In Wireshark 2.2.0 to 2.2.6, the
    ROS dissector could crash with a NULL pointer
    dereference. This was addressed in
    epan/dissectors/asn1/ros/packet-ros-template.c by
    validating an OID.(CVE-2017-9347)In Wireshark 2.2.0 to
    2.2.6 and 2.0.0 to 2.0.12, the DICOM dissector has an
    infinite loop. This was addressed in
    epan/dissectors/packet-dcm.c by validating a length
    value.(CVE-2017-9349)In Wireshark 2.6.0 to 2.6.4 and
    2.4.0 to 2.4.10, the MMSE dissector could go into an
    infinite loop. This was addressed in
    epan/dissectors/packet-mmse.c by preventing length
    overflows.(CVE-2018-19622)The dissect_dcom_OBJREF
    function in epan/dissectors/packet-dcom.c in the DCOM
    dissector in Wireshark 1.12.x before 1.12.9 does not
    initialize a certain IPv4 data structure, which allows
    remote attackers to cause a denial of service
    (application crash) via a crafted
    packet.(CVE-2015-8714)In Wireshark 2.4.0, 2.2.0 to
    2.2.8, and 2.0.0 to 2.0.14, the IrCOMM dissector has a
    buffer over-read and application crash. This was
    addressed in plugins/irda/packet-ircomm.c by adding
    length validation.(CVE-2017-13765)In Wireshark 2.4.0 to
    2.4.2 and 2.2.0 to 2.2.10, the NetBIOS dissector could
    crash. This was addressed in
    epan/dissectors/packet-netbios.c by ensuring that write
    operations are bounded by the beginning of a
    buffer.(CVE-2017-17083)The dissect_hsdsch_channel_info
    function in epan/dissectors/packet-umts_fp.c in the
    UMTS FP dissector in Wireshark 1.12.x before 1.12.9
    does not validate the number of PDUs, which allows
    remote attackers to cause a denial of service
    (application crash) via a crafted
    packet.(CVE-2015-8712)epan/dissectors/packet-umts_fp.c
    in the UMTS FP dissector in Wireshark 1.12.x before
    1.12.9 does not properly reserve memory for channel ID
    mappings, which allows remote attackers to cause a
    denial of service (out-of-bounds memory access and
    application crash) via a crafted
    packet.(CVE-2015-8713)In Wireshark 2.2.0 to 2.2.5 and
    2.0.0 to 2.0.11, the IMAP dissector could crash,
    triggered by packet injection or a malformed capture
    file. This was addressed in
    epan/dissectors/packet-imap.c by calculating a line's
    end correctly.(CVE-2017-7703)In Wireshark 2.2.0 to
    2.2.6 and 2.0.0 to 2.0.12, the DNS dissector could go
    into an infinite loop. This was addressed in
    epan/dissectors/packet-dns.c by trying to detect
    self-referencing pointers.(CVE-2017-9345)In Wireshark
    2.2.0 to 2.2.6 and 2.0.0 to 2.0.12, the Bazaar
    dissector could go into an infinite loop. This was
    addressed in epan/dissectors/packet-bzr.c by ensuring
    that backwards parsing cannot occur.(CVE-2017-9352)In
    Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to
    2.2.16, the Radiotap dissector could crash. This was
    addressed in
    epan/dissectors/packet-ieee80211-radiotap-iter.c by
    validating iterator
    operations.(CVE-2018-16057)epan/dissectors/packet-catap
    ult-dct2000.c in the Catapult DCT2000 dissector in
    Wireshark 2.x before 2.0.6 does not restrict the number
    of channels, which allows remote attackers to cause a
    denial of service (buffer over-read and application
    crash) via a crafted packet.(CVE-2016-7177)Stack-based
    buffer overflow in
    epan/dissectors/packet-catapult-dct2000.c in the
    Catapult DCT2000 dissector in Wireshark 2.x before
    2.0.6 allows remote attackers to cause a denial of
    service (application crash) via a crafted
    packet.(CVE-2016-7179)In Wireshark 2.2.0, the NCP
    dissector could crash, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/CMakeLists.txt by registering this
    dissector.(CVE-2016-7958)In Wireshark 2.2.0 to 2.2.1
    and 2.0.0 to 2.0.7, the DTN dissector could go into an
    infinite loop, triggered by network traffic or a
    capture file. This was addressed in
    epan/dissectors/packet-dtn.c by checking whether SDNV
    evaluation was
    successful.(CVE-2016-9375)epan/dissectors/packet-wbxml.
    c in the WBXML dissector in Wireshark 1.12.x before
    1.12.12 mishandles offsets, which allows remote
    attackers to cause a denial of service (integer
    overflow and infinite loop) via a crafted
    packet.(CVE-2016-5359)epan/dissectors/packet-packetbb.c
    in the PacketBB dissector in Wireshark 1.12.x before
    1.12.13 and 2.x before 2.0.5 allows remote attackers to
    cause a denial of service (divide-by-zero error and
    application crash) via a crafted
    packet.(CVE-2016-6505)epan/dissectors/packet-mmse.c in
    the MMSE dissector in Wireshark 1.12.x before 1.12.13
    allows remote attackers to cause a denial of service
    (infinite loop) via a crafted
    packet.(CVE-2016-6507)epan/dissectors/packet-rlc.c in
    the RLC dissector in Wireshark 1.12.x before 1.12.13
    and 2.x before 2.0.5 uses an incorrect integer data
    type, which allows remote attackers to cause a denial
    of service (large loop) via a crafted
    packet.(CVE-2016-6508)Off-by-one error in
    epan/dissectors/packet-rlc.c in the RLC dissector in
    Wireshark 1.12.x before 1.12.13 and 2.x before 2.0.5
    allows remote attackers to cause a denial of service
    (stack-based buffer overflow and application crash) via
    a crafted
    packet.(CVE-2016-6510)epan/dissectors/packet-iax2.c in
    the IAX2 dissector in Wireshark 1.12.x before 1.12.11
    and 2.0.x before 2.0.3 uses an incorrect integer data
    type, which allows remote attackers to cause a denial
    of service (infinite loop) via a crafted
    packet.(CVE-2016-4081)Stack-based buffer overflow in
    epan/dissectors/packet-ncp2222.inc in the NCP dissector
    in Wireshark 1.12.x before 1.12.11 allows remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    long string in a
    packet.(CVE-2016-4085)epan/dissectors/packet-dcerpc-spo
    olss.c in the SPOOLS component in Wireshark 1.12.x
    before 1.12.12 and 2.x before 2.0.4 mishandles
    unexpected offsets, which allows remote attackers to
    cause a denial of service (infinite loop) via a crafted
    packet.(CVE-2016-5350)epan/dissectors/packet-umts_fp.c
    in the UMTS FP dissector in Wireshark 1.12.x before
    1.12.12 and 2.x before 2.0.4 mishandles the reserved
    C/T value, which allows remote attackers to cause a
    denial of service (application crash) via a crafted
    packet.(CVE-2016-5353)Off-by-one error in
    epan/dissectors/packet-rsl.c in the RSL dissector in
    Wireshark 1.12.x before 1.12.10 and 2.0.x before 2.0.2
    allows remote attackers to cause a denial of service
    (out-of-bounds read and application crash) via a
    crafted packet that triggers a 0xff tag value, a
    different vulnerability than
    CVE-2016-2530.(CVE-2016-2531)The
    dissect_llrp_parameters function in
    epan/dissectors/packet-llrp.c in the LLRP dissector in
    Wireshark 1.12.x before 1.12.10 and 2.0.x before 2.0.2
    does not limit the recursion depth, which allows remote
    attackers to cause a denial of service (memory
    consumption or application crash) via a crafted
    packet.(CVE-2016-2532)epan/proto.c in Wireshark 1.12.x
    before 1.12.11 and 2.0.x before 2.0.3 does not limit
    the protocol-tree depth, which allows remote attackers
    to cause a denial of service (stack memory consumption
    and application crash) via a crafted
    packet.(CVE-2016-4006)epan/reassemble.c in TShark in
    Wireshark 2.0.x before 2.0.3 relies on incorrect
    special-case handling of truncated Tvb data structures,
    which allows remote attackers to cause a denial of
    service (use-after-free and application crash) via a
    crafted packet.(CVE-2016-4077)The AirPDcapPacketProcess
    function in epan/crypt/airpdcap.c in the 802.11
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the relationship between
    the total length and the capture length, which allows
    remote attackers to cause a denial of service
    (stack-based buffer overflow and application crash) via
    a crafted packet.(CVE-2015-8723)The ascend_seek
    function in wiretap/ascendtext.c in the Ascend file
    parser in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not ensure the presence of a '\0'
    character at the end of a date string, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read and application crash) via a
    crafted file.(CVE-2015-8729)The dissct_rsl_ipaccess_msg
    function in epan/dissectors/packet-rsl.c in the RSL
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not reject unknown TLV types, which
    allows remote attackers to cause a denial of service
    (out-of-bounds read and application crash) via a
    crafted packet.(CVE-2015-8731)The
    dissct_rsl_ipaccess_msg function in
    epan/dissectors/packet-rsl.c in the RSL dissector in
    Wireshark 1.12.x before 1.12.10 and 2.0.x before 2.0.2
    mishandles the case of an unrecognized TLV type, which
    allows remote attackers to cause a denial of service
    (out-of-bounds read and application crash) via a
    crafted packet, a different vulnerability than
    CVE-2016-2531.(CVE-2016-2530)The dnp3_al_process_object
    function in epan/dissectors/packet-dnp.c in the DNP3
    dissector in Wireshark 1.12.x before 1.12.10 and 2.0.x
    before 2.0.2 allows remote attackers to cause a denial
    of service (infinite loop) via a crafted
    packet.(CVE-2016-2523)The init_t38_info_conv function
    in epan/dissectors/packet-t38.c in the T.38 dissector
    in Wireshark 1.12.x before 1.12.9 does not ensure that
    a conversation exists, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.(CVE-2015-8716)The dissect_sdp function
    in epan/dissectors/packet-sdp.c in the SDP dissector in
    Wireshark 1.12.x before 1.12.9 does not prevent use of
    a negative media count, which allows remote attackers
    to cause a denial of service (application crash) via a
    crafted packet.(CVE-2015-8717)Double free vulnerability
    in epan/dissectors/packet-nlm.c in the NLM dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1,
    when the 'Match MSG/RES packets for async NLM' option
    is enabled, allows remote attackers to cause a denial
    of service (application crash) via a crafted
    packet.(CVE-2015-8718)The dissect_dns_answer function
    in epan/dissectors/packet-dns.c in the DNS dissector in
    Wireshark 1.12.x before 1.12.9 mishandles the EDNS0
    Client Subnet option, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.(CVE-2015-8719)Buffer overflow in the
    tvb_uncompress function in epan/tvbuff_zlib.c in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet with zlib
    compression.(CVE-2015-8721)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2425
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53098281");
  script_set_attribute(attribute:"solution", value:
"Update the affected wireshark packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["wireshark-1.10.14-7.h12",
        "wireshark-gnome-1.10.14-7.h12"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
