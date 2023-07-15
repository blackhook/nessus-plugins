#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K37111863.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(124464);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/21");

  script_cve_id("CVE-2018-12120");

  script_name(english:"F5 Networks BIG-IP : NodeJS vulnerability (K37111863)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Node.js: All versions prior to Node.js 6.15.0: Debugger port 5858
listens on any interface by default: When the debugger is enabled with
`node --debug` or `node debug`, it listens to port 5858 on all
interfaces by default. This may allow remote computers to attach to
the debug port and evaluate arbitrary JavaScript. The default
interface is now localhost. It has always been possible to start the
debugger on a specific interface, such as `node --debug=localhost`.
The debugger was removed in Node.js 8 and replaced with the inspector,
so no versions from 8 and later are vulnerable. (CVE-2018-12120)

Impact

A remote attacker may be able to attach a remote computer to the debug
port and evaluate arbitrary JavaScript."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K37111863"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K37111863."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K37111863";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["AFM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["AM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["APM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["ASM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["AVR"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["GTM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["LC"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["LTM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["PEM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");
vmatrix["WAM"]["unaffected"] = make_list("15.0.0","14.1.0.6","13.1.1.5");


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
