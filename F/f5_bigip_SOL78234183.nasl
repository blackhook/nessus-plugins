#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K78234183.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(129316);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11477");
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"F5 Networks BIG-IP : Linux SACK Panic vulnerability (K78234183) (SACK Panic)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs
value was subject to an integer overflow in the Linux kernel when
handling TCP Selective Acknowledgments (SACKs). A remote attacker
could use this to cause a denial of service. This has been fixed in
stable kernel releases 4.4.182, 4.9.182, 4.14.127, 4.19.52, 5.1.11,
and is fixed in commit 3b4929f65b0d8249f19a50245cd88ed1a2f78cff.
(CVE-2019-11477)

Impact

BIG-IP

The BIG-IP system has no exposure to this vulnerability within the
Traffic Management Microkernel (TMM), including virtual servers and
virtual IP addresses (also known as the data plane). However, the
BIG-IP system is vulnerable via the self IP addresses and the
management interface (also known as the control plane). A remote
attacker can exploit this vulnerability to cause a denial of service
(DoS) by sending a sequence of specially crafted TCP packets.

Backend systems accessed via a FastL4 virtual server

By its nature as a full-proxy, the BIG-IP system protects backend
systems accessed through a standard virtual server, as any attacker's
TCP connection would be terminated at the BIG-IP system. However,
backend systems accessed via a FastL4 virtual server(a virtual server
configured with a FastL4 profile) are exposed by default as the attack
traffic is forwarded as-is to the backend system.

Traffix SDC

A remote attacker can exploit this vulnerability to cause a denial of
service by sending a sequence of specially crafted TCP SACK packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K78234183"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K78234183."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K78234183";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.5.2-11.6.5");
vmatrix["WAM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
