#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K86272821.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(96464);
  script_version("3.14");
  script_cvs_date("Date: 2019/05/09  9:52:02");

  script_cve_id("CVE-2016-9131");

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (K86272821)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"named in ISC BIND 9.x before 9.9.9-P5, 9.10.x before 9.10.4-P5, and
9.11.x before 9.11.0-P2 allows remote attackers to cause a denial of
service (assertion failure and daemon exit) via a malformed response
to an RTYPE ANY query.(CVE-2016-9131)

Impact

When the BIND recursion option is enabled, an attacker may exploit
this vulnerability to cause the named process to restart.
Additionally, the restarted process does not trigger the BIG-IP system
high availability (HA) failover event.

By default, the BIND recursion option is not enabled on BIG-IP DNS or
GTM systems. If the BIND recursion option is enabled, BIG-IP DNS or
GTM systems are vulnerable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K86272821"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K86272821."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");
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

sol = "K86272821";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3");
vmatrix["AFM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3");
vmatrix["AM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3","11.3.0HF7","11.2.1HF9");
vmatrix["APM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2","11.3.0-11.3.0HF6","11.2.1-11.2.1HF8");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3","11.3.0HF7","11.2.1HF9");
vmatrix["ASM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2","11.3.0-11.3.0HF6","11.2.1-11.2.1HF8");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3","11.3.0HF7","11.2.1HF9");
vmatrix["AVR"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2","11.3.0-11.3.0HF6","11.2.1-11.2.1HF8");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.4.1-11.6.1","11.4.0HF3","11.3.0HF7","11.2.1HF9");
vmatrix["GTM"]["unaffected"] = make_list("11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2","11.3.0-11.3.0HF6","11.0.0-11.2.1HF8","10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3","11.3.0HF7","11.2.1HF9");
vmatrix["LC"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2","11.3.0-11.3.0HF6","11.0.0-11.2.1HF8","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3","11.3.0HF7","11.2.1HF9");
vmatrix["LTM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2","11.3.0-11.3.0HF6","11.0.0-11.2.1HF8","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.1-11.6.1","11.4.0HF3");
vmatrix["PEM"]["unaffected"] = make_list("13.1.0","13.0.0HF1","12.1.3","12.1.2HF1","11.6.2","11.5.5","11.5.4HF3","11.4.0-11.4.0HF2");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.1","11.4.0HF3");
vmatrix["PSM"]["unaffected"] = make_list("11.4.0-11.4.0HF2");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.2.1HF9");
vmatrix["WAM"]["unaffected"] = make_list("11.2.1-11.2.1HF8");


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
