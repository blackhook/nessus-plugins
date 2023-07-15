#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory tcpdump_advisory5.asc.
#

include("compat.inc");

if (description)
{
  script_id(132732);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-15166", "CVE-2019-15167");

  script_name(english:"AIX 7.2 TL 3 : tcpdump (IJ20785)");
  script_summary(english:"Check for APAR IJ20785");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14467
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14467 The BGP
parser in tcpdump before 4.9.3 has a buffer over-read in
print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_MP). The VRRP parser
in tcpdump before 4.9.3 has a buffer over-read in
print-vrrp.c:vrrp_print(). The LMP parser in tcpdump before 4.9.3 has
a buffer over-read in print-lmp.c:lmp_print_data_link_subobjs(). The
Babel parser in tcpdump before 4.9.3 has a buffer over-read in
print-babel.c:babel_print_v2(). tcpdump before 4.9.3 mishandles the
printing of SMB data (issue 2 of 2). The LDP parser in tcpdump before
4.9.3 has a buffer over-read in print-ldp.c:ldp_tlv_print(). tcpdump
before 4.9.3 mishandles the printing of SMB data (issue 1 of 2).
Tcpdump is vulnerable to a buffer overflow, caused by improper bounds
checking by the lmp_print_data_link_subobjs function in print-lmp.c.
By sending specially-crafted data, a remote attacker could overflow a
buffer and cause the application to crash. The Rx parser in tcpdump
before 4.9.3 has a buffer over-read in print-rx.c:rx_cache_find() and
rx_cache_insert(). The IKEv1 parser in tcpdump before 4.9.3 has a
buffer over-read in print-isakmp.c:ikev1_n_print(). The FRF.16 parser
in tcpdump before 4.9.3 has a buffer over-read in
print-fr.c:mfr_print(). The BGP parser in tcpdump before 4.9.3 has a
buffer over-read in print-bgp.c:bgp_capabilities_print()
(BGP_CAPCODE_RESTART). The ICMP parser in tcpdump before 4.9.3 has a
buffer over-read in print-icmp.c:icmp_print(). The OSPFv3 parser in
tcpdump before 4.9.3 has a buffer over-read in
print-ospf6.c:ospf6_print_lshdr(). The RSVP parser in tcpdump before
4.9.3 has a buffer over-read in print-rsvp.c:rsvp_obj_print(). The SMB
parser in tcpdump before 4.9.3 has buffer over-reads in
print-smb.c:print_trans() for \MAILSLOT\BROWSE and \PIPE\LANMAN. The
SMB parser in tcpdump before 4.9.3 has stack exhaustion in
smbutil.c:smb_fdata() via recursion. The BGP parser in tcpdump before
4.9.3 has a buffer over-read in print-bgp.c:bgp_attr_print()
(MP_REACH_NLRI). lmp_print_data_link_subobjs() in print-lmp.c in
tcpdump before 4.9.3 lacks certain bounds checks. The command-line
argument parser in tcpdump before 4.9.3 has a buffer overflow in
tcpdump.c:get_next_file(). The HNCP parser in tcpdump before 4.9.3 has
a buffer over-read in print-hncp.c:print_prefix(). The DCCP parser in
tcpdump before 4.9.3 has a buffer over-read in
print-dccp.c:dccp_print_option(). The IEEE 802.11 parser in tcpdump
before 4.9.3 has a buffer over-read in print-802_11.c for the Mesh
Flags subfield. The BGP parser in tcpdump before 4.9.3 allows stack
consumption in print-bgp.c:bgp_attr_print() because of unlimited
recursion. The ICMPv6 parser in tcpdump before 4.9.3 has a buffer
over-read in print-icmp6.c. tcpdump before 4.9.3 has a heap-based
buffer over-read related to aoe_print in print-aoe.c and lookup_emem
in addrtoname.c."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.2", ml:"03", sp:"01", patch:"IJ20785s1a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.16") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"03", sp:"02", patch:"IJ20785s2a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.16") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"03", sp:"03", patch:"IJ20785s3a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.16") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"03", sp:"04", patch:"IJ20785s3a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.16") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
