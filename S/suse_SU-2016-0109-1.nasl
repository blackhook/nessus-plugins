#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0109-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87911);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-7830", "CVE-2015-8711", "CVE-2015-8712", "CVE-2015-8713", "CVE-2015-8714", "CVE-2015-8715", "CVE-2015-8716", "CVE-2015-8717", "CVE-2015-8718", "CVE-2015-8719", "CVE-2015-8720", "CVE-2015-8721", "CVE-2015-8722", "CVE-2015-8723", "CVE-2015-8724", "CVE-2015-8725", "CVE-2015-8726", "CVE-2015-8727", "CVE-2015-8728", "CVE-2015-8729", "CVE-2015-8730", "CVE-2015-8731", "CVE-2015-8732", "CVE-2015-8733");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : wireshark (SUSE-SU-2016:0109-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update contains Wireshark 1.12.9 and fixes the following issues :

  - CVE-2015-7830: pcapng file parser could crash while
    copying an interface filter (bsc#950437)

  - CVE-2015-8711: epan/dissectors/packet-nbap.c in the NBAP
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate conversation data, which
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted packet.

  - CVE-2015-8712: The dissect_hsdsch_channel_info function
    in epan/dissectors/packet-umts_fp.c in the UMTS FP
    dissector in Wireshark 1.12.x before 1.12.9 does not
    validate the number of PDUs, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet.

  - CVE-2015-8713: epan/dissectors/packet-umts_fp.c in the
    UMTS FP dissector in Wireshark 1.12.x before 1.12.9 does
    not properly reserve memory for channel ID mappings,
    which allows remote attackers to cause a denial of
    service (out-of-bounds memory access and application
    crash) via a crafted packet.

  - CVE-2015-8714: The dissect_dcom_OBJREF function in
    epan/dissectors/packet-dcom.c in the DCOM dissector in
    Wireshark 1.12.x before 1.12.9 does not initialize a
    certain IPv4 data structure, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet.

  - CVE-2015-8715: epan/dissectors/packet-alljoyn.c in the
    AllJoyn dissector in Wireshark 1.12.x before 1.12.9 does
    not check for empty arguments, which allows remote
    attackers to cause a denial of service (infinite loop)
    via a crafted packet.

  - CVE-2015-8716: The init_t38_info_conv function in
    epan/dissectors/packet-t38.c in the T.38 dissector in
    Wireshark 1.12.x before 1.12.9 does not ensure that a
    conversation exists, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.

  - CVE-2015-8717: The dissect_sdp function in
    epan/dissectors/packet-sdp.c in the SDP dissector in
    Wireshark 1.12.x before 1.12.9 does not prevent use of a
    negative media count, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.

  - CVE-2015-8718: Double free vulnerability in
    epan/dissectors/packet-nlm.c in the NLM dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1,
    when the 'Match MSG/RES packets for async NLM' option is
    enabled, allows remote attackers to cause a denial of
    service (application crash) via a crafted packet.

  - CVE-2015-8719: The dissect_dns_answer function in
    epan/dissectors/packet-dns.c in the DNS dissector in
    Wireshark 1.12.x before 1.12.9 mishandles the EDNS0
    Client Subnet option, which allows remote attackers to
    cause a denial of service (application crash) via a
    crafted packet.

  - CVE-2015-8720: The dissect_ber_GeneralizedTime function
    in epan/dissectors/packet-ber.c in the BER dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    improperly checks an sscanf return value, which allows
    remote attackers to cause a denial of service
    (application crash) via a crafted packet.

  - CVE-2015-8721: Buffer overflow in the tvb_uncompress
    function in epan/tvbuff_zlib.c in Wireshark 1.12.x
    before 1.12.9 and 2.0.x before 2.0.1 allows remote
    attackers to cause a denial of service (application
    crash) via a crafted packet with zlib compression.

  - CVE-2015-8722: epan/dissectors/packet-sctp.c in the SCTP
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the frame pointer, which
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted packet.

  - CVE-2015-8723: The AirPDcapPacketProcess function in
    epan/crypt/airpdcap.c in the 802.11 dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not validate the relationship between the total
    length and the capture length, which allows remote
    attackers to cause a denial of service (stack-based
    buffer overflow and application crash) via a crafted

  - CVE-2015-8724: The AirPDcapDecryptWPABroadcastKey
    function in epan/crypt/airpdcap.c in the 802.11
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not verify the WPA broadcast key
    length, which allows remote attackers to cause a denial
    of service (out-of-bounds read and application crash)
    via a crafted packet.

  - CVE-2015-8725: The
    dissect_diameter_base_framed_ipv6_prefix function in
    epan/dissectors/packet-diameter.c in the DIAMETER
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the IPv6 prefix length,
    which allows remote attackers to cause a denial of
    service (stack-based buffer overflow and application
    crash) via a crafted packet.

  - CVE-2015-8726: wiretap/vwr.c in the VeriWave file parser
    in Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not validate certain signature and Modulation and
    Coding Scheme (MCS) data, which allows remote attackers
    to cause a denial of service (out-of-bounds read and
    application crash) via a crafted file.

  - CVE-2015-8727: The dissect_rsvp_common function in
    epan/dissectors/packet-rsvp.c in the RSVP dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not properly maintain request-key data, which
    allows remote attackers to cause a denial of service
    (use-after-free and application crash) via a crafted
    packet.

  - CVE-2015-8728: The Mobile Identity parser in (1)
    epan/dissectors/packet-ansi_a.c in the ANSI A dissector
    and (2) epan/dissectors/packet-gsm_a_common.c in the GSM
    A dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 improperly uses the
    tvb_bcd_dig_to_wmem_packet_str function, which allows
    remote attackers to cause a denial of service (buffer
    overflow and application crash) via a crafted packet.

  - CVE-2015-8729: The ascend_seek function in
    wiretap/ascendtext.c in the Ascend file parser in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not ensure the presence of a '\0' character at the
    end of a date string, which allows remote attackers to
    cause a denial of service (out-of-bounds read and
    application crash) via a crafted file.

  - CVE-2015-8730: epan/dissectors/packet-nbap.c in the NBAP
    dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x
    before 2.0.1 does not validate the number of items,
    which allows remote attackers to cause a denial of
    service (invalid read operation and application crash)
    via a crafted packet.

  - CVE-2015-8731: The dissct_rsl_ipaccess_msg function in
    epan/dissectors/packet-rsl.c in the RSL dissector in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not reject unknown TLV types, which allows remote
    attackers to cause a denial of service (out-of-bounds
    read and application crash) via a crafted packet.

  - CVE-2015-8732: The dissect_zcl_pwr_prof_pwrprofstatersp
    function in epan/dissectors/packet-zbee-zcl-general.c in
    the ZigBee ZCL dissector in Wireshark 1.12.x before
    1.12.9 and 2.0.x before 2.0.1 does not validate the
    Total Profile Number field, which allows remote
    attackers to cause a denial of service (out-of-bounds
    read and application crash) via a crafted packet.

  - CVE-2015-8733: The ngsniffer_process_record function in
    wiretap/ngsniffer.c in the Sniffer file parser in
    Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1
    does not validate the relationships between record
    lengths and record header lengths, which allows remote
    attackers to cause a denial of service (out-of-bounds
    read and application crash) via a crafted file.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7830/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8711/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8712/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8713/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8714/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8716/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8717/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8718/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8719/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8720/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8721/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8722/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8723/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8724/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8725/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8726/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8727/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8728/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8729/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8730/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8731/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8732/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8733/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160109-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c2a469e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-76=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-76=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-76=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-76=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-76=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-76=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-debuginfo-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"wireshark-debugsource-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"wireshark-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"wireshark-debuginfo-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"wireshark-debugsource-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-debuginfo-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"wireshark-debugsource-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"wireshark-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"wireshark-debuginfo-1.12.9-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"wireshark-debugsource-1.12.9-22.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
