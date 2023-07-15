#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K01512680.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150477);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/28");

  script_cve_id("CVE-2019-11811");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K01512680)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue was discovered in the Linux kernel before 5.0.4. There is a
use-after-free upon attempted read access to /proc/ioports after the
ipmi_si module is removed, related to
drivers/char/ipmi/ipmi_si_intf.c, drivers/char/ipmi/ipmi_si_mem_io.c,
and drivers/char/ipmi/ipmi_si_port_io.c.(CVE-2019-11811)

Impact

An attacker, with local access to read /proc/ioports, may be able to
create a use-after-free condition when the kernel module is unloaded,
which may result in privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K01512680"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K01512680."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K01512680";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["AFM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["AM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["APM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["ASM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["AVR"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["GTM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["LC"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["LTM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["PEM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("16.1.0","16.0.0-16.0.1","15.0.0-15.1.3","14.0.0-14.1.4","13.1.0-13.1.3");
vmatrix["WAM"]["unaffected"] = make_list("17.0.0","16.1.1","16.0.1.2","15.1.4","14.1.4.3");


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
