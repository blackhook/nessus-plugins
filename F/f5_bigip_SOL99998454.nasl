#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K99998454.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(91552);
  script_version("2.12");
  script_cvs_date("Date: 2019/05/09  9:52:02");

  script_cve_id("CVE-2016-5021");

  script_name(english:"F5 Networks BIG-IP : iControl REST vulnerability (K99998454)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The iControl REST service in F5 BIG-IP LTM, AAM, AFM, Analytics, APM,
ASM, Link Controller, and PEM 11.5.x before 11.5.4, 11.6.x before
11.6.1, and 12.x before 12.0.0 HF3; BIG-IP DNS 12.x before 12.0.0 HF3;
BIG-IP GTM 11.5.x before 11.5.4 and 11.6.x before 11.6.1; BIG-IQ Cloud
and Security 4.0.0 through 4.5.0; BIG-IQ Device 4.2.0 through 4.5.0;
BIG-IQ ADC 4.5.0; BIG-IQ Centralized Management 4.6.0; and BIG-IQ
Cloud and Orchestration 1.0.0 allows remote authenticated
administrators to obtain sensitive information via unspecified
vectors. (CVE-2016-5021)

Impact

An authenticated attacker with administrative privileges and access to
the iControl REST interface may be able to craft a malicious query
resulting in information disclosure. Because 'Common Criteria' mode
deployments disable the iControl REST service, the vulnerable code
exists, but is not exposed to a remote network access vector."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K99998454"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K99998454."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K99998454";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.3.0-11.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["AM"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.4.0-11.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["APM"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.0.0-11.4.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.0.0-11.4.1","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.0.0-11.4.1","10.1.0-10.2.4");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0","11.5.0-11.5.3");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1","11.5.4","11.0.0-11.4.1","10.1.1-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["LC"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.0.0-11.4.1","10.1.1-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.0.0-11.4.1","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0-12.0.0HF2","11.6.0","11.5.0-11.5.3");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0HF3-12.1.0","11.6.1","11.5.4","11.3.0-11.4.1");


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
