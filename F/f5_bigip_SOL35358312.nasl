#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K35358312.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(91054);
  script_version("2.11");
  script_cvs_date("Date: 2019/01/04 10:03:40");

  script_cve_id("CVE-2015-8099");

  script_name(english:"F5 Networks BIG-IP : TCP vulnerability (K35358312)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Under limited conditions, an invalid TCP segment can lead to a Denial
of Service for the High-Speed Bridge (HSB) on the following platforms:
3900, 6900, 8900, 8950, 11000, 11050, PB100 or PB200. This issue is
only exposed on virtual servers while Software SYN cookies are
configured for use and currently engaged. The scope of the exposure is
limited to the BIG-IP data plane. The access vector is network based
and authentication is not a requirement for attack. There is no
control plane exposure to this issue. (CVE-2015-8099) Note : The
affected platforms do not support the Hardware SYN cookie protection
feature. This feature appears in the profile configuration; however,
it is not configurable for the noted platforms. For more information
about SYN cookie protection, refer to K14779: Overview of BIG-IP SYN
cookie protection (11.3.x - 12.x)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K14779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K35358312"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K35358312."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
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

sol = "K35358312";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["AFM"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.4.0-11.4.1");
vmatrix["AM"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["APM"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10","11.0.0-11.2.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["ASM"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10","11.0.0-11.2.1","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["AVR"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10","11.0.0-11.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1","11.5.4","11.4.1HF10","11.0.0-11.2.1","10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["LC"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10","11.0.0-11.2.1","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["LTM"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10","11.0.0-11.2.1","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0","11.6.0","11.5.0-11.5.3","11.3.0-11.4.1");
vmatrix["PEM"]["unaffected"] = make_list("12.1.0","12.0.0HF1","11.6.1","11.5.4","11.4.1HF10");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.3.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1HF10","11.0.0-11.2.1","10.1.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.3.0");
vmatrix["WAM"]["unaffected"] = make_list("11.0.0-11.2.1","10.1.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.3.0");
vmatrix["WOM"]["unaffected"] = make_list("11.0.0-11.2.1","10.1.0-10.2.4");


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
