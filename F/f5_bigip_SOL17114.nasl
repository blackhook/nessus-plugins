#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K17114.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(105510);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2015-5146");
  script_bugtraq_id(75589);

  script_name(english:"F5 Networks BIG-IP : NTP vulnerability (K17114)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"ntpd in ntp before 4.2.8p3 with remote configuration enabled allows
remote authenticated users with knowledge of the configuration
password and access to a computer entrusted to perform remote
configuration to cause a denial of service (service crash) via a NULL
byte in a crafted configuration directive packet. (CVE-2015-5146)

An attacker can use a specially crafted package to cause ntpd to
become unresponsive when all of the following conditions are met :

The ntpd configuration has enabled remote configuration.

The attacker has knowledge of the configuration password.

The attacker has access to a computer entrusted to perform remote
configurations.

Impact

For BIG-IP systems using a default network time protocol (NTP)
configuration, there is no impact. However, BIG-IP systems with an NTP
configuration that is customized in line with the requirements of the
advisory may be vulnerable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K17114"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K17114."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K17114";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["AFM"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["AM"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["APM"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.0.0-11.3.0HF10","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["ASM"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.0.0-11.3.0HF10","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["AVR"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.0.0-11.3.0HF10");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.2.1","10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["LC"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.0.0-11.3.0HF10","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["LTM"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.0.0-11.3.0HF10","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0-12.1.1","11.6.0HF4-11.6.1","11.5.3-11.5.4","11.5.0HF7","11.4.0HF10");
vmatrix["PEM"]["unaffected"] = make_list("13.0.0-13.1.0","12.1.2-12.1.3","11.6.1HF2-11.6.2","11.6.0-11.6.0HF3","11.5.4HF3-11.5.5","11.5.1-11.5.2","11.5.0-11.5.0HF6","11.4.1-11.4.1HF11","11.4.0-11.4.0HF9","11.0.0-11.3.0HF10");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.0HF10");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1","11.0.0-11.4.0HF9","10.0.0-10.2.4");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_note(port:0, extra:bigip_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
