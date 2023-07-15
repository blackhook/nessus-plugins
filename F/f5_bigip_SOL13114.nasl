#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K13114.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78131);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);

  script_name(english:"F5 Networks BIG-IP : Apache Range header vulnerability (K13114)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The byte-range filter in the Apache HTTP Server 1.3.x, 2.0.x through
2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a
denial-of-service (memory and CPU consumption) using a Range header
that expresses multiple overlapping ranges.

When this vulnerability is exploited, the httpd process consumes all
available CPU cycles. As a result of CPU starvation, the Configuration
utility, SSH sessions, and other userland processes may appear
extremely slow or completely unresponsive. On BIG-IP systems, if the
system hardware watchdog timer is not updated for more than 10
seconds, the hardware watchdog restarts the system. (CVE-2011-3192)

Impact

The performance of userland processes may be severely impaired, and
the system may eventually reboot."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K13114"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K13114."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K13114";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.2","11.0.0");
vmatrix["APM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("9.2.0-9.4.8","10.0.0-10.2.2","11.0.0");
vmatrix["ASM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0");
vmatrix["AVR"]["unaffected"] = make_list("11.0.0HF1","11.1.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("9.2.2-9.4.8","10.0.0-10.2.2","11.0.0");
vmatrix["GTM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("9.2.2-9.4.8","10.0.0-10.2.2","11.0.0");
vmatrix["LC"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.2.2","11.0.0");
vmatrix["LTM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("9.4.0-9.4.8","10.0.0-10.2.2","11.0.0");
vmatrix["PSM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("9.4.0-9.4.8","10.0.0-10.2.2","11.0.0");
vmatrix["WAM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.0.0-10.2.2","11.0.0");
vmatrix["WOM"]["unaffected"] = make_list("10.2.2HF3","10.2.3","11.0.0HF1","11.1.0");


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
