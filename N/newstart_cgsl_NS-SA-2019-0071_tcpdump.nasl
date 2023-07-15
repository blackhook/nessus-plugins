#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0071. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127275);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-11108",
    "CVE-2017-11541",
    "CVE-2017-11542",
    "CVE-2017-11543",
    "CVE-2017-11544",
    "CVE-2017-12893",
    "CVE-2017-12894",
    "CVE-2017-12895",
    "CVE-2017-12896",
    "CVE-2017-12897",
    "CVE-2017-12898",
    "CVE-2017-12899",
    "CVE-2017-12900",
    "CVE-2017-12901",
    "CVE-2017-12902",
    "CVE-2017-12985",
    "CVE-2017-12986",
    "CVE-2017-12987",
    "CVE-2017-12988",
    "CVE-2017-12989",
    "CVE-2017-12990",
    "CVE-2017-12991",
    "CVE-2017-12992",
    "CVE-2017-12993",
    "CVE-2017-12994",
    "CVE-2017-12995",
    "CVE-2017-12996",
    "CVE-2017-12997",
    "CVE-2017-12998",
    "CVE-2017-12999",
    "CVE-2017-13000",
    "CVE-2017-13001",
    "CVE-2017-13002",
    "CVE-2017-13003",
    "CVE-2017-13004",
    "CVE-2017-13005",
    "CVE-2017-13006",
    "CVE-2017-13007",
    "CVE-2017-13008",
    "CVE-2017-13009",
    "CVE-2017-13010",
    "CVE-2017-13011",
    "CVE-2017-13012",
    "CVE-2017-13013",
    "CVE-2017-13014",
    "CVE-2017-13015",
    "CVE-2017-13016",
    "CVE-2017-13017",
    "CVE-2017-13018",
    "CVE-2017-13019",
    "CVE-2017-13020",
    "CVE-2017-13021",
    "CVE-2017-13022",
    "CVE-2017-13023",
    "CVE-2017-13024",
    "CVE-2017-13025",
    "CVE-2017-13026",
    "CVE-2017-13027",
    "CVE-2017-13028",
    "CVE-2017-13029",
    "CVE-2017-13030",
    "CVE-2017-13031",
    "CVE-2017-13032",
    "CVE-2017-13033",
    "CVE-2017-13034",
    "CVE-2017-13035",
    "CVE-2017-13036",
    "CVE-2017-13037",
    "CVE-2017-13038",
    "CVE-2017-13039",
    "CVE-2017-13040",
    "CVE-2017-13041",
    "CVE-2017-13042",
    "CVE-2017-13043",
    "CVE-2017-13044",
    "CVE-2017-13045",
    "CVE-2017-13046",
    "CVE-2017-13047",
    "CVE-2017-13048",
    "CVE-2017-13049",
    "CVE-2017-13050",
    "CVE-2017-13051",
    "CVE-2017-13052",
    "CVE-2017-13053",
    "CVE-2017-13054",
    "CVE-2017-13055",
    "CVE-2017-13687",
    "CVE-2017-13688",
    "CVE-2017-13689",
    "CVE-2017-13690",
    "CVE-2017-13725"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : tcpdump Multiple Vulnerabilities (NS-SA-2019-0071)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has tcpdump packages installed that are affected
by multiple vulnerabilities:

  - Several protocol parsers in tcpdump before 4.9.2 could
    cause a buffer over-read in util-print.c:tok2strbuf().
    (CVE-2017-12900)

  - tcpdump 4.9.0 allows remote attackers to cause a denial
    of service (heap-based buffer over-read and application
    crash) via crafted packet data. The crash occurs in the
    EXTRACT_16BITS function, called from the stp_print
    function for the Spanning Tree Protocol.
    (CVE-2017-11108)

  - A vulnerability was discovered in tcpdump's handling of
    LINKTYPE_SLIP pcap files. An attacker could craft a
    malicious pcap file that would cause tcpdump to crash
    when attempting to print a summary of packet data within
    the file. (CVE-2017-11543, CVE-2017-11544)

  - The ISO CLNS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isoclns.c:isoclns_print().
    (CVE-2017-12897)

  - The ISAKMP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isakmp.c:isakmp_rfc3948_print().
    (CVE-2017-12896)

  - The IPv6 fragmentation header parser in tcpdump before
    4.9.2 has a buffer over-read in print-
    frag6.c:frag6_print(). (CVE-2017-13031)

  - The RADIUS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-radius.c:print_attr_string().
    (CVE-2017-13032)

  - The IPv6 mobility parser in tcpdump before 4.9.2 has a
    buffer over-read in print-
    mobility.c:mobility_opt_print(). (CVE-2017-13023,
    CVE-2017-13024, CVE-2017-13025)

  - The ISO ES-IS parser in tcpdump before 4.9.2 has a
    buffer over-read in print-isoclns.c:esis_print().
    (CVE-2017-13016, CVE-2017-13047)

  - The LLDP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-lldp.c:lldp_mgmt_addr_tlv_print().
    (CVE-2017-13027)

  - The White Board protocol parser in tcpdump before 4.9.2
    has a buffer over-read in print-wb.c:wb_prep(), several
    functions. (CVE-2017-13014)

  - The IS-IS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isoclns.c:isis_print_extd_ip_reach().
    (CVE-2017-12998)

  - The IEEE 802.15.4 parser in tcpdump before 4.9.2 has a
    buffer over-read in
    print-802_15_4.c:ieee802_15_4_if_print().
    (CVE-2017-13000)

  - The ISO IS-IS parser in tcpdump before 4.9.2 has a
    buffer over-read in print-isoclns.c:isis_print_id().
    (CVE-2017-13035)

  - The OSPFv3 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-ospf6.c:ospf6_decode_v3().
    (CVE-2017-13036)

  - The ISO IS-IS parser in tcpdump before 4.9.2 has a
    buffer over-read in print-isoclns.c, several functions.
    (CVE-2017-13026)

  - The Juniper protocols parser in tcpdump before 4.9.2 has
    a buffer over-read in print-
    juniper.c:juniper_parse_header(). (CVE-2017-13004)

  - The PPP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-ppp.c:print_ccp_config_options().
    (CVE-2017-13029)

  - The IPv6 mobility parser in tcpdump before 4.9.2 has a
    buffer over-read in print-mobility.c:mobility_print().
    (CVE-2017-13009)

  - The Apple PKTAP parser in tcpdump before 4.9.2 has a
    buffer over-read in print-pktap.c:pktap_if_print().
    (CVE-2017-13007)

  - The IEEE 802.11 parser in tcpdump before 4.9.2 has a
    buffer over-read in print-802_11.c:parse_elements().
    (CVE-2017-13008, CVE-2017-12987)

  - The Juniper protocols parser in tcpdump before 4.9.2 has
    a buffer over-read in print-juniper.c, several
    functions. (CVE-2017-12993)

  - The ISAKMP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isakmp.c, several functions.
    (CVE-2017-13039)

  - The MPTCP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-mptcp.c, several functions.
    (CVE-2017-13040)

  - The ICMPv6 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-icmp6.c:icmp6_nodeinfo_print().
    (CVE-2017-13041)

  - The BGP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-bgp.c:decode_multicast_vpn().
    (CVE-2017-13043)

  - The BGP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-bgp.c:decode_rt_routing_info().
    (CVE-2017-13053)

  - The LLDP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-lldp.c:lldp_private_8023_print().
    (CVE-2017-13054)

  - The RPKI-Router parser in tcpdump before 4.9.2 has a
    buffer over-read in print-rpki-
    rtr.c:rpki_rtr_pdu_print(). (CVE-2017-13050)

  - The IKEv2 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isakmp.c, several functions.
    (CVE-2017-13690)

  - The IPv6 routing header parser in tcpdump before 4.9.2
    has a buffer over-read in print-rt6.c:rt6_print().
    (CVE-2017-13725, CVE-2017-12986)

  - The ISO IS-IS parser in tcpdump before 4.9.2 has a
    buffer over-read in print-
    isoclns.c:isis_print_is_reach_subtlv(). (CVE-2017-13055)

  - The Cisco HDLC parser in tcpdump before 4.9.2 has a
    buffer over-read in print-chdlc.c:chdlc_print().
    (CVE-2017-13687)

  - The RESP parser in tcpdump before 4.9.2 could enter an
    infinite loop due to a bug in print-
    resp.c:resp_get_length(). (CVE-2017-12989)

  - The Zephyr parser in tcpdump before 4.9.2 has a buffer
    over-read in print-zephyr.c, several functions.
    (CVE-2017-12902)

  - The DNS parser in tcpdump before 4.9.2 could enter an
    infinite loop due to a bug in print-domain.c:ns_print().
    (CVE-2017-12995)

  - Several protocol parsers in tcpdump before 4.9.2 could
    cause a buffer over-read in
    addrtoname.c:lookup_bytestring(). (CVE-2017-12894)

  - The LLDP parser in tcpdump before 4.9.2 could enter an
    infinite loop due to a bug in print-
    lldp.c:lldp_private_8021_print(). (CVE-2017-12997)

  - The ISAKMP parser in tcpdump before 4.9.2 could enter an
    infinite loop due to bugs in print-isakmp.c, several
    functions. (CVE-2017-12990)

  - A vulnerability was found in tcpdump's verbose printing
    of packet data. A crafted pcap file or specially crafted
    network traffic could cause tcpdump to write out of
    bounds in the BSS segment, potentially causing tcpdump
    to display truncated or incorrectly decoded fields or
    crash with a segmentation violation. This does not
    affect tcpdump when used with the -w option to save a
    pcap file. (CVE-2017-13011)

  - The SMB/CIFS parser in tcpdump before 4.9.2 has a buffer
    over-read in smbutil.c:name_len(). (CVE-2017-12893)

  - The ICMP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-icmp.c:icmp_print(). (CVE-2017-12895,
    CVE-2017-13012)

  - The NFS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-nfs.c:interp_reply().
    (CVE-2017-12898)

  - The DECnet parser in tcpdump before 4.9.2 has a buffer
    over-read in print-decnet.c:decnet_print().
    (CVE-2017-12899)

  - The EIGRP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-eigrp.c:eigrp_print().
    (CVE-2017-12901)

  - The IPv6 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-ip6.c:ip6_print(). (CVE-2017-12985)

  - The telnet parser in tcpdump before 4.9.2 has a buffer
    over-read in print-telnet.c:telnet_parse().
    (CVE-2017-12988)

  - The BGP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-bgp.c:bgp_attr_print().
    (CVE-2017-12991, CVE-2017-12994, CVE-2017-13046)

  - The RIPng parser in tcpdump before 4.9.2 has a buffer
    over-read in print-ripng.c:ripng_print().
    (CVE-2017-12992)

  - The PIMv2 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-pim.c:pimv2_print(). (CVE-2017-12996)

  - The IS-IS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isoclns.c:isis_print().
    (CVE-2017-12999)

  - The NFS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-nfs.c:nfs_printfh(). (CVE-2017-13001)

  - The AODV parser in tcpdump before 4.9.2 has a buffer
    over-read in print-aodv.c:aodv_extension().
    (CVE-2017-13002)

  - The LMP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-lmp.c:lmp_print(). (CVE-2017-13003)

  - The NFS parser in tcpdump before 4.9.2 has a buffer
    over-read in print-nfs.c:xid_map_enter().
    (CVE-2017-13005)

  - The L2TP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-l2tp.c, several functions.
    (CVE-2017-13006)

  - The BEEP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-beep.c:l_strnstart().
    (CVE-2017-13010)

  - The ARP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-arp.c, several functions.
    (CVE-2017-13013)

  - The EAP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-eap.c:eap_print(). (CVE-2017-13015)

  - The DHCPv6 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-dhcp6.c:dhcp6opt_print().
    (CVE-2017-13017)

  - The PGM parser in tcpdump before 4.9.2 has a buffer
    over-read in print-pgm.c:pgm_print(). (CVE-2017-13018,
    CVE-2017-13019, CVE-2017-13034)

  - The VTP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-vtp.c:vtp_print(). (CVE-2017-13020,
    CVE-2017-13033)

  - The ICMPv6 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-icmp6.c:icmp6_print().
    (CVE-2017-13021)

  - The IP parser in tcpdump before 4.9.2 has a buffer over-
    read in print-ip.c:ip_printroute(). (CVE-2017-13022)

  - The BOOTP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-bootp.c:bootp_print().
    (CVE-2017-13028)

  - The PIM parser in tcpdump before 4.9.2 has a buffer
    over-read in print-pim.c, several functions.
    (CVE-2017-13030)

  - The IP parser in tcpdump before 4.9.2 has a buffer over-
    read in print-ip.c:ip_printts(). (CVE-2017-13037)

  - The PPP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-ppp.c:handle_mlppp().
    (CVE-2017-13038)

  - The HNCP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-hncp.c:dhcpv6_print().
    (CVE-2017-13042)

  - The HNCP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-hncp.c:dhcpv4_print().
    (CVE-2017-13044)

  - The VQP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-vqp.c:vqp_print(). (CVE-2017-13045)

  - The RSVP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-rsvp.c:rsvp_obj_print().
    (CVE-2017-13048, CVE-2017-13051)

  - The Rx protocol parser in tcpdump before 4.9.2 has a
    buffer over-read in print-rx.c:ubik_print().
    (CVE-2017-13049)

  - The CFM parser in tcpdump before 4.9.2 has a buffer
    over-read in print-cfm.c:cfm_print(). (CVE-2017-13052)

  - The OLSR parser in tcpdump before 4.9.2 has a buffer
    over-read in print-olsr.c:olsr_print(). (CVE-2017-13688)

  - The IKEv1 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isakmp.c:ikev1_id_print().
    (CVE-2017-13689)

  - tcpdump 4.9.0 has a heap-based buffer over-read in the
    lldp_print function in print-lldp.c, related to util-
    print.c. (CVE-2017-11541)

  - tcpdump 4.9.0 has a heap-based buffer over-read in the
    pimv1_print function in print-pim.c. (CVE-2017-11542)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0071");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tcpdump packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "tcpdump-4.9.2-3.el7",
    "tcpdump-debuginfo-4.9.2-3.el7"
  ],
  "CGSL MAIN 5.04": [
    "tcpdump-4.9.2-3.el7",
    "tcpdump-debuginfo-4.9.2-3.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
