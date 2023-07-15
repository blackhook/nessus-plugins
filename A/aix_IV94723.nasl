#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory tcpdump_advisory3.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100467);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");

  script_name(english:"AIX 7.2 TL 1 : tcpdump (IV94723)");
  script_summary(english:"Check for APAR IV94723");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerabilities in tcpdump affect AIX :

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12993
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12993 tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the Juniper component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the RIPng component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the BGP
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the telnet component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the IEEE 802.11 component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the IPv6 routing headers component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the IPv6
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the Zephyr component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the EIGRP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the
tok2strbuf component. By sending a specially crafted request, an
attacker could exploit this vulnerability to obtain sensitive
information. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the DECnet
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the NFS component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the ISO CLNS component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the ISAKMP component. By sending a specially crafted request, an
attacker could exploit this vulnerability to obtain sensitive
information. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the ICMP component.
By sending a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the lookup_bytestring component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the SMB/CIFS component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump is vulnerable to a denial of
service, caused by a heap-based buffer over-read in the pimv1_print
function in print-pim.c. An attacker could exploit this vulnerability
to cause the application to crash. tcpdump is vulnerable to a denial
of service, caused by a heap-based buffer over-read in the lldp_print
function in print-lldp.c. An attacker could exploit this vulnerability
to cause the application to crash. tcpdump is vulnerable to a denial
of service, caused by an error in the LLDP component. By sending
specially crafted data, a remote attacker could exploit this
vulnerability to cause the application to enter into an infinite loop.
tcpdump is vulnerable to a denial of service, caused by an error in
the DNS component. By sending specially crafted data, a remote
attacker could exploit this vulnerability to cause the application to
enter into an infinite loop. tcpdump is vulnerable to a denial of
service, caused by an error in the ISAKMP component. By sending
specially crafted data, a remote attacker could exploit this
vulnerability to cause the application to enter into an infinite loop.
tcpdump is vulnerable to a denial of service, caused by an error in
the RESP component. By sending specially crafted data, a remote
attacker could exploit this vulnerability to cause the application to
enter into an infinite loop. tcpdump is vulnerable to a buffer
overflow, caused by improper bounds checking by the
bittok2str_internal component. By sending an overly long string
argument, a remote attacker could overflow a buffer and execute
arbitrary code on the system or cause the application to crash.
tcpdump is vulnerable to a denial of service, caused by a buffer
overflow in the sliplink_print function in print-sl.c. An attacker
could exploit this vulnerability to cause the application to crash.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the PGM component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the DHCPv6 component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the ISO ES-IS component. By sending a specially crafted request, an
attacker could exploit this vulnerability to obtain sensitive
information. tcpdump is vulnerable to a denial of service, caused by a
buffer overflow in the sliplink_print function in print-sl.c. An
attacker could exploit this vulnerability to cause the application to
crash. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the EAP component.
By sending a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the White Board component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the ARP component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the ICMP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the BEEP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the IPv6
mobility component. By sending a specially crafted request, an
attacker could exploit this vulnerability to obtain sensitive
information. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the IEEE 802.11
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the L2TP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the NFS component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the
Juniper component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the LMP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the AODV component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the NFS
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the IEEE 802.15.4 component. By sending
a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the ISO IS-IS component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the ISO IS-IS component. By sending a specially crafted request, an
attacker could exploit this vulnerability to obtain sensitive
information. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the PIMv2
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the BGP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump is vulnerable
to a denial of service, caused by a heap-based buffer over-read in the
lldp_print function in print-lldp.c. An attacker could exploit this
vulnerability to cause the application to crash. tcpdump is vulnerable
to a denial of service, caused by a heap-based buffer over-read in the
pimv1_print function in print-pim.c. An attacker could exploit this
vulnerability to cause the application to crash. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the BGP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the HNCP
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the ICMPv6 component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the MPTCP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the
ISAKMP component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the PPP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the IP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the
OSPFv3 component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the ISO IS-IS component. By
sending a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the PGM component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the VTP
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the RADIUS component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the IPv6 fragmentation header component. By sending
a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the PIM component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the PPP
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the BOOTP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the LLDP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the ISO
IS-IS component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the IPv6 mobility component. By
sending a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the IPv6 mobility component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the IPv6 mobility component. By sending a specially crafted request,
an attacker could exploit this vulnerability to obtain sensitive
information. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the IP component.
By sending a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the ICMPv6 component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the VTP component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the PGM component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the IPv6 routing headers component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the IKEv2 component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the IKEv1
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the OLSR component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the Cisco HDLC component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the ISO IS-IS component. By sending a specially crafted request, an
attacker could exploit this vulnerability to obtain sensitive
information. tcpdump could allow a remote attacker to obtain sensitive
information, caused by a buffer overread memory in the LLDP component.
By sending a specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the BGP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information. tcpdump could allow a remote attacker to obtain
sensitive information, caused by a buffer overread memory in the CFM
component. By sending a specially crafted request, an attacker could
exploit this vulnerability to obtain sensitive information. tcpdump
could allow a remote attacker to obtain sensitive information, caused
by a buffer overread memory in the RSVP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the RPKI-Router component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the Rx component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the RSVP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the ISO ES-IS component. By sending a specially
crafted request, an attacker could exploit this vulnerability to
obtain sensitive information. tcpdump could allow a remote attacker to
obtain sensitive information, caused by a buffer overread memory in
the BGP component. By sending a specially crafted request, an attacker
could exploit this vulnerability to obtain sensitive information.
tcpdump could allow a remote attacker to obtain sensitive information,
caused by a buffer overread memory in the VQP component. By sending a
specially crafted request, an attacker could exploit this
vulnerability to obtain sensitive information. tcpdump could allow a
remote attacker to obtain sensitive information, caused by a buffer
overread memory in the HNCP component. By sending a specially crafted
request, an attacker could exploit this vulnerability to obtain
sensitive information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"7.2", ml:"01", sp:"01", patch:"IV94723m3a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.1.0", maxfilesetver:"7.2.1.1") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"01", sp:"02", patch:"IV94723m3a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.1.0", maxfilesetver:"7.2.1.1") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"01", sp:"03", patch:"IV94723m3a", package:"bos.net.tcp.tcpdump", minfilesetver:"7.2.1.0", maxfilesetver:"7.2.1.1") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
