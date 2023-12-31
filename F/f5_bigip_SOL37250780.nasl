#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K37250780.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(93247);
  script_version("2.7");
  script_cvs_date("Date: 2019/12/31");

  script_name(english:"F5 Networks BIG-IP : TMOS vulnerability: Password changes for local users may not be preserved unless the configuration is explicitly saved (K37250780)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When changing local user passwords at first boot, the password update
may not be preserved unless the configuration is explicitly saved.
This will leave the system in a state where it still accepts the old
password, and the new password cannot be used to log in.

This vulnerability occurs when all of the following conditions are 
met :

You have upgraded your BIG-IP system to a version listed in the
Versions known to be vulnerable column in the Security Advisory Status
table.

You restart the BIG-IP system for the first time.

After rebooting, the BIG-IP system prompts you to change the password
due to password expiration.

The BIG-IP configuration reloads without being saved. Note : The
BIG-IP configuration may be implicitly reloaded in many cases,
including system restart, mcpd process restarting, and license
installation.

Impact

Users cannot log in to the BIG-IP, BIG-IQ, F5 iWorkflow, or Enterprise
Manager system using the most recent password, due to the new password
being overwritten by the previous password. Additionally, local users
are prompted to change their passwords, multiple times, due to
password expiration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K37250780"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K37250780."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K37250780";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3");
vmatrix["AFM"]["unaffected"] = make_list("14.0.0","13.1.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3");
vmatrix["AM"]["unaffected"] = make_list("14.0.0","13.1.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3","11.2.1");
vmatrix["APM"]["unaffected"] = make_list("14.0.0","13.1.0","10.2.1-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3","11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("14.0.0","13.1.0","10.2.1-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3","11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("14.0.0","13.1.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.4.0-11.6.3","11.2.1");
vmatrix["GTM"]["unaffected"] = make_list("10.2.1-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3","11.2.1");
vmatrix["LC"]["unaffected"] = make_list("13.1.0","10.2.1-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3","11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("14.0.0","13.1.0","10.2.1-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0-13.0.1","12.0.0-12.1.3","11.4.0-11.6.3");
vmatrix["PEM"]["unaffected"] = make_list("14.0.0","13.1.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("10.2.1-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("10.2.1-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.2.1");
vmatrix["WOM"]["unaffected"] = make_list("10.2.1-10.2.4");


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
