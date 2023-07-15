#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K74413297.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(104194);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2014-3184");
  script_bugtraq_id(69768);

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K74413297)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The report_fixup functions in the HID subsystem in the Linux kernel
before 3.16.2 might allow physically proximate attackers to cause a
denial of service (out-of-bounds write) via a crafted device that
provides a small report descriptor, related to (1)
drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c, (5)
drivers/hid/hid-petalynx.c, and (6) drivers/hid/hid-sunplus.c.
(CVE-2014-3184)

Impact

An attacker may be able to gain access to unauthorized information,
perform unauthorized modification of data, or cause disruption of
services. This vulnerability requires physical access to the device."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K74413297"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K74413297."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K74413297";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["AFM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["AM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["APM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.1","11.5.1-11.5.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.2","11.5.5");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["LC"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0","11.6.1","11.5.1-11.5.4","11.2.1");
vmatrix["PEM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2","11.6.2","11.5.5");


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
