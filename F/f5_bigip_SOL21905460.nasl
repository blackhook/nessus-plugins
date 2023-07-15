#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K21905460.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(104687);
  script_version("3.16");
  script_cvs_date("Date: 2019/07/17 16:36:41");

  script_cve_id("CVE-2017-6168");

  script_name(english:"F5 Networks BIG-IP : BIG-IP SSL vulnerability (K21905460) (ROBOT)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"On BIG-IP versions 11.6.0-11.6.2 (fixed in 11.6.2 HF1), 12.0.0-12.1.2
HF1 (fixed in 12.1.2 HF2), or 13.0.0-13.0.0 HF2 (fixed in 13.0.0 HF3)
a virtual server configured with a Client SSL profile may be
vulnerable to an Adaptive Chosen Ciphertext attack (AKA Bleichenbacher
attack) against RSA, which when exploited, may result in plaintext
recovery of encrypted messages and/or a Man-in-the-middle (MiTM)
attack, despite the attacker not having gained access to the server's
private key itself, aka a ROBOT attack. (CVE-2017-6168)

Impact

Exploiting this vulnerability to perform plaintext recovery of
encrypted messages will, in most practical cases, allow an attacker to
read the plaintext only after the session has completed. Only TLS
sessions established using RSA key exchange are vulnerable to this
attack.

Exploiting this vulnerability to conduct a MiTM attack requires the
attacker to complete the initial attack, which may require millions of
server requests, during the handshake phase of the targeted
sessionwithin the window of the configured handshake timeout. This
attack may be conducted against any TLS session using RSA signatures,
but only if cipher suites using RSA key exchange are also enabled on
the virtual server. The limited window of opportunity, limitations in
bandwidth, and latencymake this attack significantly more difficult to
execute.

This vulnerability affects BIG-IP systems with the following
configuration :

A virtual server associated with a Client SSL profile with RSA key
exchange enabled; RSA key exchange is enabled by default.Captured TLS
sessions encrypted with ephemeral cipher suites (DHE or ECDHE) are not
at risk for subsequent decryption due to this vulnerability.

Important :

Virtual servers configured with a Client SSL profile with the Generic
Alert option disabled (enabled by default) are at higher risk because
they report the specific handshake failure instead of a generic
message.

Virtual servers configured with a Client SSL profile that has the
Client Certificate option under the Client Authentication section set
to require will limit the threat to attackers that are able to
successfully authenticate first. Without client certificate
authentication, this attack is unauthenticated andanonymous.

Virtual servers that have completely disabled RSA Key Exchange cipher
suites within the Client SSL profile (for example, cipher string
DEFAULT:!RSA ) are NOT impacted by this vulnerability.

BIG-IP Configuration utility, iControl services, big3d collection
agent, and Centralized Management Infrastructure (CMI) connections are
NOT impacted by this vulnerability.

Captured traffic from sessions using Perfect Forward Secrecy (PFS)
cipher suites (DHE or ECDHE) cannot be decrypted due to this
vulnerability.

This vulnerability is not an RSA private key recovery attack and does
not compromise the servers private key."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K21905460"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K21905460."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K21905460";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["AFM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["AM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["APM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7","11.2.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["ASM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7","11.2.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["AVR"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7","11.2.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["LC"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7","11.2.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["LTM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7","11.2.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.2");
vmatrix["PEM"]["unaffected"] = make_list("14.0.0","13.1.0","13.0.0HF3","12.1.3","12.1.2HF2","11.6.3","11.6.2HF1","11.5.1-11.5.7");


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
