#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K80533167.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(97333);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2015-3135", "CVE-2017-3135");
  script_bugtraq_id(75592);

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (K80533167)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Under some conditions when using both DNS64 and RPZ to rewrite query
responses, query processing can resume in an inconsistent state
leading to either an INSIST assertion failure or an attempt to read
through a NULL pointer. Affects BIND 9.8.8, 9.9.3-S1 -> 9.9.9-S7,
9.9.3 -> 9.9.9-P5, 9.9.10b1, 9.10.0 -> 9.10.4-P5, 9.10.5b1, 9.11.0 ->
9.11.0-P2, 9.11.1b1. (CVE-2015-3135)

BIG-IP configurations using DNS64 (the DNS IPv6 to IPv4 option
configured in the DNS profile) and Response Policy Zone (RPZ)
rewriting (in the BIND configuration) together are affected by this
CVE.

Note : The DNS IPv6 to IPv4 option is disabled, by default, in the DNS
profile.

Note : RPZ Rewriting is an optional BIND 9.x configuration that allows
administrators to create DNS deny lists.

Impact

Remote attackers may be able to cause a BIND denial-of-service (DoS)
attack by making a query for an AAAA record."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K80533167"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K80533167."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K80533167";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["AFM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["AM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["APM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7","11.2.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["ASM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7","11.2.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["AVR"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7","11.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["GTM"]["unaffected"] = make_list("11.6.2","11.5.6","11.4.1-11.4.1HF7","11.2.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["LC"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7","11.2.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["LTM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7","11.2.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.5","11.4.1HF8");
vmatrix["PEM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.2HF1","11.6.2","11.5.6","11.4.1-11.4.1HF7");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.1HF8");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1-11.4.1HF7");


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
