#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1205.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104239);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11108", "CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");

  script_name(english:"openSUSE Security Update : tcpdump (openSUSE-2017-1205)");
  script_summary(english:"Check for the openSUSE-2017-1205 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tcpdump to version 4.9.2 fixes several issues.

These security issues were fixed :

  - CVE-2017-11108: Prevent remote attackers to cause DoS
    (heap-based buffer over-read and application crash) via
    crafted packet data. The crash occured in the
    EXTRACT_16BITS function, called from the stp_print
    function for the Spanning Tree Protocol (bsc#1047873,
    bsc#1057247).

  - CVE-2017-11543: Prevent buffer overflow in the
    sliplink_print function in print-sl.c that allowed
    remote DoS (bsc#1057247).

  - CVE-2017-13011: Prevent buffer overflow in
    bittok2str_internal() that allowed remote DoS
    (bsc#1057247)

  - CVE-2017-12989: Prevent infinite loop in the RESP parser
    that allowed remote DoS (bsc#1057247)

  - CVE-2017-12990: Prevent infinite loop in the ISAKMP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12995: Prevent infinite loop in the DNS parser
    that allowed remote DoS (bsc#1057247)

  - CVE-2017-12997: Prevent infinite loop in the LLDP parser
    that allowed remote DoS (bsc#1057247)

  - CVE-2017-11541: Prevent heap-based buffer over-read in
    the lldp_print function in print-lldp.c, related to
    util-print.c that allowed remote DoS (bsc#1057247).

  - CVE-2017-11542: Prevent heap-based buffer over-read in
    the pimv1_print function in print-pim.c that allowed
    remote DoS (bsc#1057247).

  - CVE-2017-12893: Prevent buffer over-read in the SMB/CIFS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12894: Prevent buffer over-read in several
    protocol parsers that allowed remote DoS (bsc#1057247)

  - CVE-2017-12895: Prevent buffer over-read in the ICMP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12896: Prevent buffer over-read in the ISAKMP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12897: Prevent buffer over-read in the ISO CLNS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12898: Prevent buffer over-read in the NFS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12899: Prevent buffer over-read in the DECnet
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12900: Prevent buffer over-read in the in
    several protocol parsers that allowed remote DoS
    (bsc#1057247)

  - CVE-2017-12901: Prevent buffer over-read in the EIGRP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12902: Prevent buffer over-read in the Zephyr
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12985: Prevent buffer over-read in the IPv6
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12986: Prevent buffer over-read in the IPv6
    routing header parser that allowed remote DoS
    (bsc#1057247)

  - CVE-2017-12987: Prevent buffer over-read in the 802.11
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12988: Prevent buffer over-read in the telnet
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12991: Prevent buffer over-read in the BGP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12992: Prevent buffer over-read in the RIPng
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12993: Prevent buffer over-read in the Juniper
    protocols parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12994: Prevent buffer over-read in the BGP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12996: Prevent buffer over-read in the PIMv2
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12998: Prevent buffer over-read in the IS-IS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-12999: Prevent buffer over-read in the IS-IS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13000: Prevent buffer over-read in the IEEE
    802.15.4 parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13001: Prevent buffer over-read in the NFS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13002: Prevent buffer over-read in the AODV
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13003: Prevent buffer over-read in the LMP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13004: Prevent buffer over-read in the Juniper
    protocols parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13005: Prevent buffer over-read in the NFS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13006: Prevent buffer over-read in the L2TP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13007: Prevent buffer over-read in the Apple
    PKTAP parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13008: Prevent buffer over-read in the IEEE
    802.11 parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13009: Prevent buffer over-read in the IPv6
    mobility parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13010: Prevent buffer over-read in the BEEP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13012: Prevent buffer over-read in the ICMP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13013: Prevent buffer over-read in the ARP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13014: Prevent buffer over-read in the White
    Board protocol parser that allowed remote DoS
    (bsc#1057247)

  - CVE-2017-13015: Prevent buffer over-read in the EAP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13016: Prevent buffer over-read in the ISO
    ES-IS parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13017: Prevent buffer over-read in the DHCPv6
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13018: Prevent buffer over-read in the PGM
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13019: Prevent buffer over-read in the PGM
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13020: Prevent buffer over-read in the VTP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13021: Prevent buffer over-read in the ICMPv6
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13022: Prevent buffer over-read in the IP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13023: Prevent buffer over-read in the IPv6
    mobility parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13024: Prevent buffer over-read in the IPv6
    mobility parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13025: Prevent buffer over-read in the IPv6
    mobility parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13026: Prevent buffer over-read in the ISO
    IS-IS parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13027: Prevent buffer over-read in the LLDP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13028: Prevent buffer over-read in the BOOTP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13029: Prevent buffer over-read in the PPP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13030: Prevent buffer over-read in the PIM
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13031: Prevent buffer over-read in the IPv6
    fragmentation header parser that allowed remote DoS
    (bsc#1057247)

  - CVE-2017-13032: Prevent buffer over-read in the RADIUS
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13033: Prevent buffer over-read in the VTP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13034: Prevent buffer over-read in the PGM
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13035: Prevent buffer over-read in the ISO
    IS-IS parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13036: Prevent buffer over-read in the OSPFv3
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13037: Prevent buffer over-read in the IP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13038: Prevent buffer over-read in the PPP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13039: Prevent buffer over-read in the ISAKMP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13040: Prevent buffer over-read in the MPTCP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13041: Prevent buffer over-read in the ICMPv6
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13042: Prevent buffer over-read in the HNCP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13043: Prevent buffer over-read in the BGP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13044: Prevent buffer over-read in the HNCP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13045: Prevent buffer over-read in the VQP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13046: Prevent buffer over-read in the BGP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13047: Prevent buffer over-read in the ISO
    ES-IS parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13048: Prevent buffer over-read in the RSVP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13049: Prevent buffer over-read in the Rx
    protocol parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13050: Prevent buffer over-read in the
    RPKI-Router parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13051: Prevent buffer over-read in the RSVP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13052: Prevent buffer over-read in the CFM
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13053: Prevent buffer over-read in the BGP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13054: Prevent buffer over-read in the LLDP
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13055: Prevent buffer over-read in the ISO
    IS-IS parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13687: Prevent buffer over-read in the Cisco
    HDLC parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13688: Prevent buffer over-read in the OLSR
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13689: Prevent buffer over-read in the IKEv1
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13690: Prevent buffer over-read in the IKEv2
    parser that allowed remote DoS (bsc#1057247)

  - CVE-2017-13725: Prevent buffer over-read in the IPv6
    routing header parser that allowed remote DoS
    (bsc#1057247)

  - Prevent segmentation fault in ESP decoder with OpenSSL
    1.1 (bsc#1057247)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057247"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"tcpdump-4.9.2-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tcpdump-debuginfo-4.9.2-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tcpdump-debugsource-4.9.2-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tcpdump-4.9.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tcpdump-debuginfo-4.9.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tcpdump-debugsource-4.9.2-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump / tcpdump-debuginfo / tcpdump-debugsource");
}
