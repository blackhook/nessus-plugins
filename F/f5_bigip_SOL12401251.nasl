#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K12401251.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(92846);
  script_version("2.12");
  script_cvs_date("Date: 2019/05/09  9:52:02");

  script_cve_id("CVE-2015-8022");

  script_name(english:"F5 Networks BIG-IP : BIG-IP  file validation vulnerability (K12401251)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Configuration utility in F5 BIG-IP LTM, Analytics, APM, ASM, GTM,
and Link Controller 11.x before 11.2.1 HF16, 11.3.x, 11.4.x before
11.4.1 HF10, 11.5.x before 11.5.4, and 11.6.x before 11.6.1; BIG-IP
AAM 11.4.x before 11.4.1 HF10, 11.5.x before 11.5.4, and 11.6.x before
11.6.1; BIG-IP AFM and PEM 11.3.x, 11.4.x before 11.4.1 HF10, 11.5.x
before 11.5.4, and 11.6.x before 11.6.1; BIG-IP Edge Gateway,
WebAccelerator, and WOM 11.x before 11.2.1 HF16 and 11.3.0; and BIG-IP
PSM 11.x before 11.2.1 HF16, 11.3.x, and 11.4.x before 11.4.1 HF10
allows remote authenticated users with certain permissions to gain
privileges by leveraging an Access Policy Manager customization
configuration section that allows file uploads. (CVE-2015-8022)

Impact

An authenticated attacker mayupload files to the BIG-IP system.
Privilege escalation maypotentially occur when attackers authenticate
with at least Application Editor privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K12401251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K12401251."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/11");
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

sol = "K12401251";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.4.0-11.4.1HF9");
vmatrix["AM"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["APM"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10","11.2.1HF16","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10","11.2.1HF16","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10","11.2.1HF16");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1","11.5.4","11.4.1HF10","11.2.1HF16","10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["LC"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10","11.2.1HF16","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10","11.2.1HF16","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1HF9");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0-12.1.0","11.6.1","11.5.4","11.4.1HF10");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.3.0-11.4.1HF9","11.0.0-11.2.1HF15");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1HF10","11.2.1HF16","10.1.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.3.0","11.0.0-11.2.1HF15");
vmatrix["WAM"]["unaffected"] = make_list("11.2.1HF16","10.1.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.3.0","11.0.0-11.2.1HF15");
vmatrix["WOM"]["unaffected"] = make_list("11.2.1HF16","10.1.0-10.2.4");


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
