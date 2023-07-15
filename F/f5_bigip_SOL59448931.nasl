#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K59448931.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(105442);
  script_version("3.12");
  script_cvs_date("Date: 2019/03/06 15:30:34");

  script_cve_id("CVE-2017-3142");

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (K59448931)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An attacker who is able to send and receive messages to an
authoritative DNS server and who has knowledge of a valid TSIG key
name may be able to circumvent TSIG authentication of AXFR requests
via a carefully constructed request packet. A server that relies
solely on TSIG keys for protection with no other ACL protection could
be manipulated into: providing an AXFR of a zone to an unauthorized
recipient or accepting bogus NOTIFY packets. Affects BIND
9.4.0->9.8.8, 9.9.0->9.9.10-P1, 9.10.0->9.10.5-P1, 9.11.0->9.11.1-P1,
9.9.3-S1->9.9.10-S2, 9.10.5-S1->9.10.5-S2. (CVE-2017-3142)

Impact

BIG-IP

An attacker may be permitted to view the entire contents of a zone
when the vulnerability is exploited. For the BIG-IP system to be
considered vulnerable, it must have the allow-transfer statement with
TSIG authentication configured in BIND. This configuration combination
is not a default configuration.

F5 iWorkflow, BIG-IQ, and Enterprise Manager

There is no impact. Although the BIG-IQ and Enterprise Manager
software contain the vulnerable code, the BIG-IQ and Enterprise
Manager systems do not use the vulnerable code in a way that exposes
the vulnerability in default, standard, or recommended configurations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K59448931"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K59448931."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
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

sol = "K59448931";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2");
vmatrix["AFM"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2");
vmatrix["AM"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2","11.2.1");
vmatrix["APM"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2","11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2","11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.4.0-11.6.2","11.2.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.3","11.5.6");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2","11.2.1");
vmatrix["LC"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2","11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.3","11.4.0-11.6.2");
vmatrix["PEM"]["unaffected"] = make_list("14.0.0","13.1.0","11.6.3","11.5.6");


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
