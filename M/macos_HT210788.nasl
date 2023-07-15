#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131957);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2012-1164",
    "CVE-2012-2668",
    "CVE-2013-4449",
    "CVE-2015-1545",
    "CVE-2017-16808",
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
    "CVE-2018-14470",
    "CVE-2018-14879",
    "CVE-2018-14880",
    "CVE-2018-14881",
    "CVE-2018-14882",
    "CVE-2018-16227",
    "CVE-2018-16228",
    "CVE-2018-16229",
    "CVE-2018-16230",
    "CVE-2018-16300",
    "CVE-2018-16301",
    "CVE-2018-16451",
    "CVE-2018-16452",
    "CVE-2019-8828",
    "CVE-2019-8830",
    "CVE-2019-8832",
    "CVE-2019-8833",
    "CVE-2019-8837",
    "CVE-2019-8838",
    "CVE-2019-8839",
    "CVE-2019-8842",
    "CVE-2019-8847",
    "CVE-2019-8848",
    "CVE-2019-8852",
    "CVE-2019-8853",
    "CVE-2019-8856",
    "CVE-2019-13057",
    "CVE-2019-13565",
    "CVE-2019-15161",
    "CVE-2019-15162",
    "CVE-2019-15163",
    "CVE-2019-15164",
    "CVE-2019-15165",
    "CVE-2019-15166",
    "CVE-2019-15167",
    "CVE-2019-15903"
  );
  script_bugtraq_id(
    52404,
    53823,
    63190,
    72519
  );
  script_xref(name:"APPLE-SA", value:"HT210788");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-12-06");

  script_name(english:"macOS 10.15.x < 10.15.2 / 10.14.x < 10.14.6 Security Update 2019-002 / 10.13.x < 10.13.6 Security Update 2019-007");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.13.x prior
to 10.13.6 Security Update 2019-007, 10.14.x prior to 10.14.6 Security Update
2019-002, or 10.15.x prior to 10.15.2. It is, therefore, affected by multiple
vulnerabilities :

  - slapd in OpenLDAP before 2.4.30 allows remote attackers
    to cause a denial of service (assertion failure and
    daemon exit) via an LDAP search query with attrsOnly set
    to true, which causes empty attributes to be returned.
    (CVE-2012-1164)

  - libraries/libldap/tls_m.c in OpenLDAP, possibly 2.4.31
    and earlier, when using the Mozilla NSS backend, always
    uses the default cipher suite even when TLSCipherSuite
    is set, which might cause OpenLDAP to use weaker ciphers
    than intended and make it easier for remote attackers to
    obtain sensitive information. (CVE-2012-2668)

  - The rwm overlay in OpenLDAP 2.4.23, 2.4.36, and earlier
    does not properly count references, which allows remote
    attackers to cause a denial of service (slapd crash) by
    unbinding immediately after a search request, which
    triggers rwm_conn_destroy to free the session context
    while it is being used by rwm_op_search. (CVE-2013-4449)

  - The deref_parseCtrl function in
    servers/slapd/overlays/deref.c in OpenLDAP 2.4.13
    through 2.4.40 allows remote attackers to cause a denial
    of service (NULL pointer dereference and crash) via an
    empty attribute list in a deref control in a search
    request. (CVE-2015-1545)

  - tcpdump before 4.9.3 has a heap-based buffer over-read
    related to aoe_print in print-aoe.c and lookup_emem in
    addrtoname.c. (CVE-2017-16808)

  - tcpdump before 4.9.3 mishandles the printing of SMB data
    (issue 1 of 2). (CVE-2018-10103)

  - tcpdump before 4.9.3 mishandles the printing of SMB data
    (issue 2 of 2). (CVE-2018-10105)

  - The LDP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-ldp.c:ldp_tlv_print().
    (CVE-2018-14461)

  - The ICMP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-icmp.c:icmp_print(). (CVE-2018-14462)

  - The VRRP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-vrrp.c:vrrp_print(). (CVE-2018-14463)

  - The LMP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-lmp.c:lmp_print_data_link_subobjs().
    (CVE-2018-14464)

  - The RSVP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-rsvp.c:rsvp_obj_print().
    (CVE-2018-14465)

  - The Rx parser in tcpdump before 4.9.3 has a buffer over-
    read in print-rx.c:rx_cache_find() and
    rx_cache_insert(). (CVE-2018-14466)

  - The BGP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_MP). (CVE-2018-14467)

  - The FRF.16 parser in tcpdump before 4.9.3 has a buffer
    over-read in print-fr.c:mfr_print(). (CVE-2018-14468)

  - The IKEv1 parser in tcpdump before 4.9.3 has a buffer
    over-read in print-isakmp.c:ikev1_n_print().
    (CVE-2018-14469)

  - The Babel parser in tcpdump before 4.9.3 has a buffer
    over-read in print-babel.c:babel_print_v2().
    (CVE-2018-14470)

  - The command-line argument parser in tcpdump before 4.9.3
    has a buffer overflow in tcpdump.c:get_next_file().
    (CVE-2018-14879)

  - The OSPFv3 parser in tcpdump before 4.9.3 has a buffer
    over-read in print-ospf6.c:ospf6_print_lshdr().
    (CVE-2018-14880)

  - The BGP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_RESTART). (CVE-2018-14881)

  - The ICMPv6 parser in tcpdump before 4.9.3 has a buffer
    over-read in print-icmp6.c. (CVE-2018-14882)

  - The IEEE 802.11 parser in tcpdump before 4.9.3 has a
    buffer over-read in print-802_11.c for the Mesh Flags
    subfield. (CVE-2018-16227)

  - The HNCP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-hncp.c:print_prefix().
    (CVE-2018-16228)

  - The DCCP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-dccp.c:dccp_print_option().
    (CVE-2018-16229)

  - The BGP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-bgp.c:bgp_attr_print()
    (MP_REACH_NLRI). (CVE-2018-16230)

  - The BGP parser in tcpdump before 4.9.3 allows stack
    consumption in print-bgp.c:bgp_attr_print() because of
    unlimited recursion. (CVE-2018-16300)

  - libpcap before 1.9.1, as used in tcpdump before 4.9.3,
    has a buffer overflow and/or over-read because of errors
    in pcapng reading. (CVE-2018-16301)

  - The SMB parser in tcpdump before 4.9.3 has buffer over-
    reads in print-smb.c:print_trans() for \MAILSLOT\BROWSE
    and \PIPE\LANMAN. (CVE-2018-16451)

  - The SMB parser in tcpdump before 4.9.3 has stack
    exhaustion in smbutil.c:smb_fdata() via recursion.
    (CVE-2018-16452)

  - An issue was discovered in the server in OpenLDAP before
    2.4.48. When the server administrator delegates rootDN
    (database admin) privileges for certain databases but
    wants to maintain isolation (e.g., for multi-tenant
    deployments), slapd does not properly stop a rootDN from
    requesting authorization as an identity from another
    database during a SASL bind or with a proxyAuthz (RFC
    4370) control. (It is not a common configuration to
    deploy a system where the server administrator and a DB
    administrator enjoy different levels of trust.)
    (CVE-2019-13057)

  - An issue was discovered in OpenLDAP 2.x before 2.4.48.
    When using SASL authentication and session encryption,
    and relying on the SASL security layers in slapd access
    controls, it is possible to obtain access that would
    otherwise be denied via a simple bind for any identity
    covered in those ACLs. After the first SASL bind is
    completed, the sasl_ssf value is retained for all new
    non-SASL connections. Depending on the ACL
    configuration, this can affect different types of
    operations (searches, modifications, etc.). In other
    words, a successful authorization step completed by one
    user affects the authorization requirement for a
    different user. (CVE-2019-13565)

  - rpcapd/daemon.c in libpcap before 1.9.1 mishandles
    certain length values because of reuse of a variable.
    This may open up an attack vector involving extra data
    at the end of a request. (CVE-2019-15161)

  - rpcapd/daemon.c in libpcap before 1.9.1 on non-Windows
    platforms provides details about why authentication
    failed, which might make it easier for attackers to
    enumerate valid usernames. (CVE-2019-15162)

  - rpcapd/daemon.c in libpcap before 1.9.1 allows attackers
    to cause a denial of service (NULL pointer dereference
    and daemon crash) if a crypt() call fails.
    (CVE-2019-15163)

  - rpcapd/daemon.c in libpcap before 1.9.1 allows SSRF
    because a URL may be provided as a capture source.
    (CVE-2019-15164)

  - sf-pcapng.c in libpcap before 1.9.1 does not properly
    validate the PHB header length before allocating memory.
    (CVE-2019-15165)

  - lmp_print_data_link_subobjs() in print-lmp.c in tcpdump
    before 4.9.3 lacks certain bounds checks.
    (CVE-2019-15166)

  - In libexpat before 2.2.8, crafted XML input could fool
    the parser into changing from DTD parsing to document
    parsing too early; a consecutive call to
    XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read.
    (CVE-2019-15903)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210788");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.2 / 10.14.x < 10.14.6 Security Update 2019-002 / 10.13.x < 10.13.6 Security Update 2019-007 or
later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8852");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10105");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '10.15', 'fixed_version' : '10.15.2' },
  { 'min_version' : '10.13', 'max_version' : '10.13.6', 'fixed_build': '17G10021', 'fixed_display' : '10.13.6 Security Update 2019-007' },
  { 'min_version' : '10.14', 'max_version' : '10.14.6', 'fixed_build': '18G2022', 'fixed_display' : '10.14.6 Security Update 2019-002' }
];
vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
