#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K05123525.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(129076);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-6649");

  script_name(english:"F5 Networks BIG-IP : ConfigSync vulnerability (K05123525)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"F5 BIG-IP and Enterprise Manager may expose sensitive information and
allow the system configuration to be modified when using non-default
ConfigSync settings.(CVE-2019-6649)

Impact

The vulnerability is only present when the system is configured for
high availability (HA)and either of the following settings are used :

ConfigSync is using a self IP with Port Lockdown configured as Allow
All .

Note : Port Lockdown defaults to Allow None .

ConfigSync is configured to use the management interface.The database
variable configsync.allowmanagement must be set to enable to allow
this configuration (default is disable ).Check the configuration by
typing the following command at the shell prompt: tmsh list /sys db
configsync.allowmanagement

Note : This is an uncommon configuration.

Systems that are not running with either configuration are not
affected.

Note : BIG-IQ systems and iWorkflow systems are not affected.

In both of the previously described configurations, a malicious actor
may be able to connect to the interface used for ConfigSync to extract
and/or modify sensitive information on the system.

Additionally, when ConfigSync is configured to use the management
interface, sensitive information may be transmitted unencrypted,
risking information disclosure to and modification by anyone in the
path of the traffic."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K05123525"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K05123525."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K05123525";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["AFM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["AM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["APM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["ASM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["AVR"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["GTM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["LC"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["LTM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["PEM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("15.0.0","14.1.0","14.0.0","13.1.0-13.1.1","12.1.0-12.1.4","11.6.1-11.6.4","11.5.2-11.5.9");
vmatrix["WAM"]["unaffected"] = make_list("15.0.1","14.1.2","14.0.1","13.1.3","12.1.5","11.6.5","11.5.10");


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
