#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K05013313.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(88428);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2015-4047");
  script_bugtraq_id(74739);

  script_name(english:"F5 Networks BIG-IP : IPsec vulnerability (K05013313)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"racoon/gssapi.c in IPsec-Tools 0.8.2 allows remote attackers to cause
a denial of service (NULL pointer dereference and IKE daemon crash)
via a series of crafted UDP requests. (CVE-2015-4047)

Impact

When this vulnerability is exploited, the remote attacker may be able
use crafted UDP requests to cause the racoon process to stop
responding, resulting in a denial-of-service (DoS) attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K05013313"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K05013313."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K05013313";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.3.0-11.6.4");
vmatrix["AFM"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.4.0-11.6.4");
vmatrix["AM"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.0.0-11.6.4");
vmatrix["APM"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.0.0-11.6.4");
vmatrix["ASM"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.0.0-11.6.4");
vmatrix["AVR"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.6.4");
vmatrix["GTM"]["unaffected"] = make_list("10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.0.0-11.6.4");
vmatrix["LC"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.0.0-11.6.4");
vmatrix["LTM"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.5","11.3.0-11.6.4");
vmatrix["PEM"]["unaffected"] = make_list("14.0.0-14.1.0","13.1.0-13.1.1");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.0.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("10.1.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.0.0-11.3.0");
vmatrix["WAM"]["unaffected"] = make_list("10.1.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.0.0-11.3.0");
vmatrix["WOM"]["unaffected"] = make_list("10.1.0-10.2.4");


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
