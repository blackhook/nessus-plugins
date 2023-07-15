#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K91158923.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(140470);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-5929");
  script_xref(name:"IAVA", value:"2020-A-0395-S");

  script_name(english:"F5 Networks BIG-IP : BIG-IP SSL/TLS ADH/DHE vulnerability (K91158923)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"BIG-IP platforms with Cavium Nitrox SSL hardware acceleration cards, a
virtual server configured with a Client SSL profile, and using
AnonymousDiffie-Hellman (ADH) or Ephemeral Diffie-Hellman(DHE) key
exchange and Single DH use option not enabled in the options list may
be vulnerable to crafted SSL/Transport Layer Security (TLS) handshakes
that may result with a pre-master secret (PMS)that starts in a 0 byte
and may lead to a recovery of plaintext messages as BIG-IP TLS/SSL
ADH/DHE sends different error messages acting as an oracle.
Differences in processing time when the PMS starts with 0 byte coupled
with very precise timing measurement observation may also expose this
vulnerability. (CVE-2020-5929)

Impact

Exploiting this vulnerability requires multiple crafted SSL/TLS
handshakes to the vulnerable BIG-IP virtual server. This vulnerability
may make it possible to recover the shared secret of past sessions and
perform plaintext recovery of encrypted messages.Only SSL/TLS sessions
established using cipher suites that use ADH or DHEkey exchange are
vulnerable to this attack. Captured SSL/TLS sessions encrypted with
cipher suites using the RSA key exchange are not at risk for
subsequent decryption due to this vulnerability.

This vulnerability affects BIG-IP systems with virtual servers
associated with a Client SSL profile and only if all of the following
conditions are met :

You are using ADH or DHE key exchange in the Client SSL profile. Note
:DHE is enabled by defaultin the DEFAULT cipher suite. ADH is not
available in the DEFAULT cipher suite.

You have not enabled the Single Diffie-Hellman use optionor Single DH
use optionin the Client SSL profile. Note : The Single DHuse optionis
not enabled by default in the Client SSL profile options list.

Your BIG-IP platform has a Cavium Nitrox SSL hardware acceleration
card installed. Platforms with this installed include: BIG-IP
i11400-DS, i11600-DS, i11800-DS

BIG-IP 800, 1600, 3600, 3900, 5000, 6900, 7000, 8900, 10000, 11000,
12000

VIPRION 2100, 2150, 2250, 4100, 4200, 4300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K91158923"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K91158923."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K91158923";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["AFM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["AM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["APM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["ASM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["AVR"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["GTM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["LC"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["LTM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.1.0-12.1.2HF1","11.6.1-11.6.2");
vmatrix["PEM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_note(port:0, extra:bigip_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
