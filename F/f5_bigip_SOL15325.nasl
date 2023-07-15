#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K15325.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78174);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);

  script_name(english:"F5 Networks BIG-IP : OpenSSL vulnerability (K15325)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
does not properly restrict processing of ChangeCipherSpec messages,
which allows man-in-the-middle attackers to trigger use of a
zero-length master key in certain OpenSSL-to-OpenSSL communications,
and consequently hijack sessions or obtain sensitive information, via
a crafted TLS handshake, aka the 'CCS Injection' vulnerability.
(CVE-2014-0224)

Impact

An attacker may be able to decrypt and modify traffic between a client
and a server. OpenSSL clients may be vulnerable to a man-in-the-middle
(MITM) attack when connecting to a server running OpenSSL 1.0.1 or
1.0.2. For information about vulnerable components or features, refer
to the following section.

Server-side impact for F5 products

The server-side components are vulnerable in the event that an
attacker is able to launch an MITM attack between a client and an
affected server component.

BIG-IP 11.5.0 through 11.5.1 contains the following vulnerable
server-side code :

COMPAT SSL ciphers are vulnerable. Virtual servers using a Client SSL
profile configured to use ciphers from the COMPAT SSL stack are
vulnerable to this attack (the BIG-IP Client SSL profile enables the
BIG-IP system to accept and terminate client requests that are sent
using the SSL protocol; in this context, the BIG-IP functions as an
SSL server, handling incoming SSL traffic). Note : NATIVE SSL ciphers
on affected versions are not vulnerable. However, some vulnerability
scanners may generate false positive reports when run against BIG-IP
virtual servers that are configured to use ciphers supported by the
NATIVE SSL stack. This includes all ciphers enabled by the default
cipher string.

Note: On non-vulnerable versions, the third-party nmap script,
ssl-ccs-injection.nse , may return a false positive vulnerable report
if the Generic Alert option of the Client SSL profile is enabled
(enabled by default). You can safely ignore this result and it does
not indicate that the BIG-IP virtual server is vulnerable, but is an
artifact of the basic check performed by the nmap script. F5 does not
recommend disabling generic alerts because they provide a significant
security advantage compared tothe potential small disadvantage of this
false positive report.

The Configuration utility and other services, such as iControl, are
vulnerable.

The big3d process included with BIG-IP GTM 11.5.0 and 11.5.1 is
vulnerable. In addition, monitored BIG-IP systems whose big3d process
was updated by an affected BIG-IP GTM system are also vulnerable.

Client-side impact for F5 products

Connections that a vulnerable F5 device initiates (as a client) are at
risk in the event that an attacker gains access to the traffic between
the F5 device and the server (for example, BIG-IP system and pool
members), and the server with which the F5 device is communicating is
running a vulnerable version of OpenSSL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K15325"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K15325."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/15");
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

sol = "K15325";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.3.0-11.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.4.0-11.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.0.0-11.4.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.0.0-11.4.1","10.0.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.0.0-11.4.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.0.0-11.4.1","10.0.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.0.0-11.4.1","10.0.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.0.0-11.4.1","10.0.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.5.0","11.5.1");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.3","11.5.2","11.5.1HF3","11.5.0HF4","11.3.0-11.4.1");


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
