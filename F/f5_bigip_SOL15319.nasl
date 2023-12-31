#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K15319.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(78173);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2014-0196");
  script_bugtraq_id(67199, 67282);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"F5 Networks BIG-IP : Linux kernel TTY vulnerability (K15319)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel
through 3.14.3 does not properly manage tty driver access in the
'LECHO & !OPOST' case, which allows local users to cause a denial of
service (memory corruption and system crash) or gain privileges by
triggering a race condition involving read and write operations with
long strings. (CVE-2014-0196)

Impact

Local users may be able to cause a denial-of-service (DoS) or gain
privileges by triggering a race condition.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K15319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K15319.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

sol = "K15319";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.5.1");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.5.1");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.1.0-11.5.1");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.1.0-11.5.1");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.1.0-11.5.1");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.1.0-11.5.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.1.0-11.5.1");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.1.0-11.5.1");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.5.1");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.0","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.1.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.1.0-11.3.0");
vmatrix["WAM"]["unaffected"] = make_list("11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.1.0-11.3.0");
vmatrix["WOM"]["unaffected"] = make_list("11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");


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
