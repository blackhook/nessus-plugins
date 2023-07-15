#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K57211290.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(101493);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/09");

  script_cve_id("CVE-2016-10142");

  script_name(english:"F5 Networks BIG-IP : IPv6 fragmentation vulnerability (K57211290)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in the IPv6 protocol specification, related to
ICMP Packet Too Big (PTB) messages. (The scope of this CVE is all
affected IPv6 implementations from all vendors.) The security
implications of IP fragmentation have been discussed at length in
[RFC6274] and [RFC7739]. An attacker can leverage the generation of
IPv6 atomic fragments to trigger the use of fragmentation in an
arbitrary IPv6 flow (in scenarios in which actual fragmentation of
packets is not needed) and can subsequently perform any type of
fragmentation-based attack against legacy IPv6 nodes that do not
implement [RFC6946]. That is, employing fragmentation where not
actually needed allows for fragmentation-based attack vectors to be
employed, unnecessarily. We note that, unfortunately, even nodes that
already implement [RFC6946] can be subject to DoS attacks as a result
of the generation of IPv6 atomic fragments. Let us assume that Host A
is communicating with Host B and that, as a result of the widespread
dropping of IPv6 packets that contain extension headers (including
fragmentation) [RFC7872], some intermediate node filters fragments
between Host B and Host A. If an attacker sends a forged ICMPv6 PTB
error message to Host B, reporting an MTU smaller than 1280, this will
trigger the generation of IPv6 atomic fragments from that moment on
(as required by [RFC2460]). When Host B starts sending IPv6 atomic
fragments (in response to the received ICMPv6 PTB error message),
these packets will be dropped, since we previously noted that IPv6
packets with extension headers were being dropped between Host B and
Host A. Thus, this situation will result in a DoS scenario. Another
possible scenario is that in which two BGP peers are employing IPv6
transport and they implement Access Control Lists (ACLs) to drop IPv6
fragments (to avoid control-plane attacks). If the aforementioned BGP
peers drop IPv6 fragments but still honor received ICMPv6 PTB error
messages, an attacker could easily attack the corresponding peering
session by simply sending an ICMPv6 PTB message with a reported MTU
smaller than 1280 bytes. Once the attack packet has been sent, the
aforementioned routers will themselves be the ones dropping their own
traffic. (CVE-2016-10142)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K57211290"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K57211290."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K57211290";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.4.1-11.5.8");
vmatrix["AFM"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.0","12.0.0-12.1.3","11.6.0-11.6.3","11.5.9");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.4.1-11.5.8");
vmatrix["AM"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.1","12.0.0-12.1.4","11.6.0-11.6.3","11.5.9");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.2.1","11.4.1-11.5.8","11.2.1");
vmatrix["APM"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.0","12.0.0-12.1.3","11.6.0-11.6.3","11.5.9");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.2.1","11.4.1-11.5.8","11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.0","12.0.0-12.1.3","11.6.0-11.6.3","11.5.9");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.2.1","11.4.1-11.5.8","11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.0","12.0.0-12.1.3","11.6.0-11.6.3","11.5.9");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0-11.6.1","11.4.1-11.5.4","11.2.1","11.4.1-11.5.8","11.2.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.2-11.6.3","11.5.5-11.5.8","11.6.0-11.6.3","11.5.9");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.2.1","11.4.1-11.5.8","11.2.1");
vmatrix["LC"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.1","12.0.0-12.1.4","11.6.0-11.6.3","11.5.9");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.1-11.5.4","11.2.1","11.4.1-11.5.8","11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.1","12.0.0-12.1.4","11.6.0-11.6.3","11.5.9");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.4.0-11.5.4","11.4.1-11.5.8");
vmatrix["PEM"]["unaffected"] = make_list("13.0.0-13.1.1","12.1.3-12.1.4","11.6.2-11.6.3","11.5.5-11.5.8","13.0.0-13.1.1","12.0.0-12.1.4","11.6.0-11.6.3","11.5.9");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_warning(port:0, extra:bigip_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
