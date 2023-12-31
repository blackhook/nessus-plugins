#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL13607.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78137);
  script_version("1.8");
  script_cvs_date("Date: 2019/01/04 10:03:40");

  script_name(english:"F5 Networks BIG-IP : Hosts may generate weak RSA keys under low entropy conditions (SOL13607)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A recent study, linked in the Supplemental Information section, has
revealed that when a system generates new RSA keys under low-entropy
conditions, such as during the first system boot, the resulting keys
may not be cryptographically strong."
  );
  # http://eprint.iacr.org/2012/064.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"https://eprint.iacr.org/2012/064.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K13607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL13607."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "SOL13607";
vmatrix = make_array();

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.1.0-10.2.3");
vmatrix["APM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3","9.0.0-9.4.8");
vmatrix["ASM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0");
vmatrix["AVR"]["unaffected"] = make_list("11.1.0HF3");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3","9.0.0-9.4.8");
vmatrix["GTM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3","9.0.0-9.4.8");
vmatrix["LC"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3","9.0.0-9.4.8");
vmatrix["LTM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3","9.0.0-9.4.8");
vmatrix["PSM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3","9.0.0-9.4.8");
vmatrix["WAM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.1.0-11.1.0HF2","11.0.0-11.0.0","10.0.0-10.2.3");
vmatrix["WOM"]["unaffected"] = make_list("11.1.0HF3","10.2.4");


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
