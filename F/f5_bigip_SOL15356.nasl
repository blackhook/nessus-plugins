#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K15356.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78180);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2014-0195");
  script_bugtraq_id(67900);

  script_name(english:"F5 Networks BIG-IP : OpenSSL vulnerability (K15356)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before
0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not
properly validate fragment lengths in DTLS ClientHello messages, which
allows remote attackers to execute arbitrary code or cause a denial of
service (buffer overflow and application crash) via a long non-initial
fragment. (CVE-2014-0195)

Impact

An attacker may be able to exploit an OpenSSL Datagram Transport Layer
Security (DTLS) client or server by sending invalid DTLS fragments. As
a result, the attacker may be able to run arbitrary code or cause a
denial-of-service (DoS).

Server-side impact for F5 products

The server-side components are vulnerable in the event that an
attacker is able to launch an attack from a client to an affected
server component. BIG-IP 11.3.0 and earlier contains the following
vulnerable server-side code :

COMPAT SSL ciphers Virtual servers using a ClientSSL profile
configured to use ciphers from the COMPAT SSL stack are vulnerable to
this attack. The BIG-IP ClientSSL profile enables the BIG-IP system to
accept and terminate client requests that are sent using the SSL
protocol. In this context, the BIG-IP system functions as an SSL
server, handling incoming SSL traffic.

Note : NATIVE SSL ciphers on affected versions are not vulnerable.
However, some vulnerability scanners may generate false positive
reports when run against BIG-IP virtual servers that are configured to
use ciphers supported by the NATIVE SSL stack. This includes all
ciphers enabled by the default cipher string.

Client-side impact for F5 products

The client-side components are vulnerable in the event that an
attacker is able to launch an attack from a server to an affected
client component. BIG-IP 11.5.1 and earlier contains the following
vulnerable server-side code :

COMPAT SSL ciphers Virtual servers using a ServerSSL profile
configured to use ciphers from the COMPAT SSL stack are vulnerable to
this attack. The BIG-IP ServerSSL profile enables the BIG-IP system to
initiate secure connections to SSL servers using the SSL protocol. In
this context, the BIG-IP system functions as an SSL client, initiating
outbound SSL traffic.

Host-initiated SSL connections An example here is when you use openssl
s_client or configure a DTLS monitor to initiate SSL connections."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K15356"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K15356."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K15356";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0");
vmatrix["AFM"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.3.0");
vmatrix["AVR"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0");
vmatrix["PEM"]["unaffected"] = make_list("11.6.0","11.4.0-11.5.3");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["PSM"]["unaffected"] = make_list("11.4.0-11.4.1");


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
