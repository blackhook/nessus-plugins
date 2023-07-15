#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14191-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2017-12893",
    "CVE-2017-12894",
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
    "CVE-2017-12991",
    "CVE-2017-12992",
    "CVE-2017-12993",
    "CVE-2017-12995",
    "CVE-2017-12996",
    "CVE-2017-12998",
    "CVE-2017-12999",
    "CVE-2017-13001",
    "CVE-2017-13002",
    "CVE-2017-13003",
    "CVE-2017-13004",
    "CVE-2017-13005",
    "CVE-2017-13006",
    "CVE-2017-13008",
    "CVE-2017-13009",
    "CVE-2017-13010",
    "CVE-2017-13012",
    "CVE-2017-13013",
    "CVE-2017-13014",
    "CVE-2017-13016",
    "CVE-2017-13017",
    "CVE-2017-13018",
    "CVE-2017-13019",
    "CVE-2017-13021",
    "CVE-2017-13022",
    "CVE-2017-13023",
    "CVE-2017-13024",
    "CVE-2017-13025",
    "CVE-2017-13027",
    "CVE-2017-13028",
    "CVE-2017-13029",
    "CVE-2017-13030",
    "CVE-2017-13031",
    "CVE-2017-13032",
    "CVE-2017-13034",
    "CVE-2017-13035",
    "CVE-2017-13036",
    "CVE-2017-13037",
    "CVE-2017-13038",
    "CVE-2017-13041",
    "CVE-2017-13047",
    "CVE-2017-13048",
    "CVE-2017-13049",
    "CVE-2017-13051",
    "CVE-2017-13053",
    "CVE-2017-13055",
    "CVE-2017-13687",
    "CVE-2017-13688",
    "CVE-2017-13689",
    "CVE-2017-13725",
    "CVE-2018-10103",
    "CVE-2018-10105",
    "CVE-2018-14461",
    "CVE-2018-14462",
    "CVE-2018-14463",
    "CVE-2018-14464",
    "CVE-2018-14465",
    "CVE-2018-14466",
    "CVE-2018-14467",
    "CVE-2018-14468",
    "CVE-2018-14469",
    "CVE-2018-14881",
    "CVE-2018-14882",
    "CVE-2018-16229",
    "CVE-2018-16230",
    "CVE-2018-16300",
    "CVE-2018-16301",
    "CVE-2018-16451",
    "CVE-2018-16452",
    "CVE-2019-15166"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14191-1");

  script_name(english:"SUSE SLES11 Security Update : tcpdump (SUSE-SU-2019:14191-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14191-1 advisory.

  - The SMB/CIFS parser in tcpdump before 4.9.2 has a buffer over-read in smbutil.c:name_len().
    (CVE-2017-12893)

  - Several protocol parsers in tcpdump before 4.9.2 could cause a buffer over-read in
    addrtoname.c:lookup_bytestring(). (CVE-2017-12894)

  - The ISAKMP parser in tcpdump before 4.9.2 has a buffer over-read in print-isakmp.c:isakmp_rfc3948_print().
    (CVE-2017-12896)

  - The ISO CLNS parser in tcpdump before 4.9.2 has a buffer over-read in print-isoclns.c:isoclns_print().
    (CVE-2017-12897)

  - The NFS parser in tcpdump before 4.9.2 has a buffer over-read in print-nfs.c:interp_reply().
    (CVE-2017-12898)

  - The DECnet parser in tcpdump before 4.9.2 has a buffer over-read in print-decnet.c:decnet_print().
    (CVE-2017-12899)

  - Several protocol parsers in tcpdump before 4.9.2 could cause a buffer over-read in util-
    print.c:tok2strbuf(). (CVE-2017-12900)

  - The EIGRP parser in tcpdump before 4.9.2 has a buffer over-read in print-eigrp.c:eigrp_print().
    (CVE-2017-12901)

  - The Zephyr parser in tcpdump before 4.9.2 has a buffer over-read in print-zephyr.c, several functions.
    (CVE-2017-12902)

  - The IPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-ip6.c:ip6_print().
    (CVE-2017-12985)

  - The IPv6 routing header parser in tcpdump before 4.9.2 has a buffer over-read in print-rt6.c:rt6_print().
    (CVE-2017-12986, CVE-2017-13725)

  - The IEEE 802.11 parser in tcpdump before 4.9.2 has a buffer over-read in print-802_11.c:parse_elements().
    (CVE-2017-12987, CVE-2017-13008)

  - The telnet parser in tcpdump before 4.9.2 has a buffer over-read in print-telnet.c:telnet_parse().
    (CVE-2017-12988)

  - The BGP parser in tcpdump before 4.9.2 has a buffer over-read in print-bgp.c:bgp_attr_print().
    (CVE-2017-12991)

  - The RIPng parser in tcpdump before 4.9.2 has a buffer over-read in print-ripng.c:ripng_print().
    (CVE-2017-12992)

  - The Juniper protocols parser in tcpdump before 4.9.2 has a buffer over-read in print-juniper.c, several
    functions. (CVE-2017-12993)

  - The DNS parser in tcpdump before 4.9.2 could enter an infinite loop due to a bug in print-
    domain.c:ns_print(). (CVE-2017-12995)

  - The PIMv2 parser in tcpdump before 4.9.2 has a buffer over-read in print-pim.c:pimv2_print().
    (CVE-2017-12996)

  - The IS-IS parser in tcpdump before 4.9.2 has a buffer over-read in print-
    isoclns.c:isis_print_extd_ip_reach(). (CVE-2017-12998)

  - The IS-IS parser in tcpdump before 4.9.2 has a buffer over-read in print-isoclns.c:isis_print().
    (CVE-2017-12999)

  - The NFS parser in tcpdump before 4.9.2 has a buffer over-read in print-nfs.c:nfs_printfh().
    (CVE-2017-13001)

  - The AODV parser in tcpdump before 4.9.2 has a buffer over-read in print-aodv.c:aodv_extension().
    (CVE-2017-13002)

  - The LMP parser in tcpdump before 4.9.2 has a buffer over-read in print-lmp.c:lmp_print(). (CVE-2017-13003)

  - The Juniper protocols parser in tcpdump before 4.9.2 has a buffer over-read in print-
    juniper.c:juniper_parse_header(). (CVE-2017-13004)

  - The NFS parser in tcpdump before 4.9.2 has a buffer over-read in print-nfs.c:xid_map_enter().
    (CVE-2017-13005)

  - The L2TP parser in tcpdump before 4.9.2 has a buffer over-read in print-l2tp.c, several functions.
    (CVE-2017-13006)

  - The IPv6 mobility parser in tcpdump before 4.9.2 has a buffer over-read in print-
    mobility.c:mobility_print(). (CVE-2017-13009)

  - The BEEP parser in tcpdump before 4.9.2 has a buffer over-read in print-beep.c:l_strnstart().
    (CVE-2017-13010)

  - The ICMP parser in tcpdump before 4.9.2 has a buffer over-read in print-icmp.c:icmp_print().
    (CVE-2017-13012)

  - The ARP parser in tcpdump before 4.9.2 has a buffer over-read in print-arp.c, several functions.
    (CVE-2017-13013)

  - The White Board protocol parser in tcpdump before 4.9.2 has a buffer over-read in print-wb.c:wb_prep(),
    several functions. (CVE-2017-13014)

  - The ISO ES-IS parser in tcpdump before 4.9.2 has a buffer over-read in print-isoclns.c:esis_print().
    (CVE-2017-13016, CVE-2017-13047)

  - The DHCPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-dhcp6.c:dhcp6opt_print().
    (CVE-2017-13017)

  - The PGM parser in tcpdump before 4.9.2 has a buffer over-read in print-pgm.c:pgm_print(). (CVE-2017-13018,
    CVE-2017-13019, CVE-2017-13034)

  - The ICMPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-icmp6.c:icmp6_print().
    (CVE-2017-13021)

  - The IP parser in tcpdump before 4.9.2 has a buffer over-read in print-ip.c:ip_printroute().
    (CVE-2017-13022)

  - The IPv6 mobility parser in tcpdump before 4.9.2 has a buffer over-read in print-
    mobility.c:mobility_opt_print(). (CVE-2017-13023, CVE-2017-13024, CVE-2017-13025)

  - The LLDP parser in tcpdump before 4.9.2 has a buffer over-read in print-lldp.c:lldp_mgmt_addr_tlv_print().
    (CVE-2017-13027)

  - The BOOTP parser in tcpdump before 4.9.2 has a buffer over-read in print-bootp.c:bootp_print().
    (CVE-2017-13028)

  - The PPP parser in tcpdump before 4.9.2 has a buffer over-read in print-ppp.c:print_ccp_config_options().
    (CVE-2017-13029)

  - The PIM parser in tcpdump before 4.9.2 has a buffer over-read in print-pim.c, several functions.
    (CVE-2017-13030)

  - The IPv6 fragmentation header parser in tcpdump before 4.9.2 has a buffer over-read in print-
    frag6.c:frag6_print(). (CVE-2017-13031)

  - The RADIUS parser in tcpdump before 4.9.2 has a buffer over-read in print-radius.c:print_attr_string().
    (CVE-2017-13032)

  - The ISO IS-IS parser in tcpdump before 4.9.2 has a buffer over-read in print-isoclns.c:isis_print_id().
    (CVE-2017-13035)

  - The OSPFv3 parser in tcpdump before 4.9.2 has a buffer over-read in print-ospf6.c:ospf6_decode_v3().
    (CVE-2017-13036)

  - The IP parser in tcpdump before 4.9.2 has a buffer over-read in print-ip.c:ip_printts(). (CVE-2017-13037)

  - The PPP parser in tcpdump before 4.9.2 has a buffer over-read in print-ppp.c:handle_mlppp().
    (CVE-2017-13038)

  - The ICMPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-icmp6.c:icmp6_nodeinfo_print().
    (CVE-2017-13041)

  - The RSVP parser in tcpdump before 4.9.2 has a buffer over-read in print-rsvp.c:rsvp_obj_print().
    (CVE-2017-13048, CVE-2017-13051)

  - The Rx protocol parser in tcpdump before 4.9.2 has a buffer over-read in print-rx.c:ubik_print().
    (CVE-2017-13049)

  - The BGP parser in tcpdump before 4.9.2 has a buffer over-read in print-bgp.c:decode_rt_routing_info().
    (CVE-2017-13053)

  - The ISO IS-IS parser in tcpdump before 4.9.2 has a buffer over-read in print-
    isoclns.c:isis_print_is_reach_subtlv(). (CVE-2017-13055)

  - The Cisco HDLC parser in tcpdump before 4.9.2 has a buffer over-read in print-chdlc.c:chdlc_print().
    (CVE-2017-13687)

  - The OLSR parser in tcpdump before 4.9.2 has a buffer over-read in print-olsr.c:olsr_print().
    (CVE-2017-13688)

  - The IKEv1 parser in tcpdump before 4.9.2 has a buffer over-read in print-isakmp.c:ikev1_id_print().
    (CVE-2017-13689)

  - tcpdump before 4.9.3 mishandles the printing of SMB data (issue 1 of 2). (CVE-2018-10103)

  - tcpdump before 4.9.3 mishandles the printing of SMB data (issue 2 of 2). (CVE-2018-10105)

  - The LDP parser in tcpdump before 4.9.3 has a buffer over-read in print-ldp.c:ldp_tlv_print().
    (CVE-2018-14461)

  - The ICMP parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp.c:icmp_print().
    (CVE-2018-14462)

  - The VRRP parser in tcpdump before 4.9.3 has a buffer over-read in print-vrrp.c:vrrp_print().
    (CVE-2018-14463)

  - The LMP parser in tcpdump before 4.9.3 has a buffer over-read in print-
    lmp.c:lmp_print_data_link_subobjs(). (CVE-2018-14464)

  - The RSVP parser in tcpdump before 4.9.3 has a buffer over-read in print-rsvp.c:rsvp_obj_print().
    (CVE-2018-14465)

  - The Rx parser in tcpdump before 4.9.3 has a buffer over-read in print-rx.c:rx_cache_find() and
    rx_cache_insert(). (CVE-2018-14466)

  - The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_MP). (CVE-2018-14467)

  - The FRF.16 parser in tcpdump before 4.9.3 has a buffer over-read in print-fr.c:mfr_print().
    (CVE-2018-14468)

  - The IKEv1 parser in tcpdump before 4.9.3 has a buffer over-read in print-isakmp.c:ikev1_n_print().
    (CVE-2018-14469)

  - The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_RESTART). (CVE-2018-14881)

  - The ICMPv6 parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp6.c. (CVE-2018-14882)

  - The DCCP parser in tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option().
    (CVE-2018-16229)

  - The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_attr_print()
    (MP_REACH_NLRI). (CVE-2018-16230)

  - The BGP parser in tcpdump before 4.9.3 allows stack consumption in print-bgp.c:bgp_attr_print() because of
    unlimited recursion. (CVE-2018-16300)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2018-16301)

  - The SMB parser in tcpdump before 4.9.3 has buffer over-reads in print-smb.c:print_trans() for
    \MAILSLOT\BROWSE and \PIPE\LANMAN. (CVE-2018-16451)

  - The SMB parser in tcpdump before 4.9.3 has stack exhaustion in smbutil.c:smb_fdata() via recursion.
    (CVE-2018-16452)

  - lmp_print_data_link_subobjs() in print-lmp.c in tcpdump before 4.9.3 lacks certain bounds checks.
    (CVE-2019-15166)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1057247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153332");
  # https://www.suse.com/support/update/announcement/2019/suse-su-201914191-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e03f0e89");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14461");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14462");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14467");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16452");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15166");
  script_set_attribute(attribute:"solution", value:
"Update the affected tcpdump package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'tcpdump-3.9.8-1.30.13', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'tcpdump-3.9.8-1.30.13', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tcpdump');
}
