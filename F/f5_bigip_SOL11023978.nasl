#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/02/19.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K11023978.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(107106);
  script_version("3.9");
  script_cvs_date("Date: 2020/02/19");

  script_cve_id("CVE-2017-6346");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K11023978) (Deprecated)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Race condition in net/packet/af_packet.c in the Linux kernel before
4.9.13 allows local users to cause a denial of service
(use-after-free) or possibly have unspecified other impact via a
multithreaded application that makes PACKET_FANOUT setsockopt system
calls. (CVE-2017-6346) - No F5 Systems are Impacted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K11023978"
  );
  script_set_attribute(
    attribute:"solution", 
    value: "n/a"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}
exit(0, "This plugin has been deprecated because F5 products are not affected by this vulnerability.");

include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K11023978";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["AM"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["APM"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4","11.2.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4","11.2.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4","11.2.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["LC"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4","11.2.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4","11.2.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.0.0-13.1.1");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0-12.1.4","11.4.0-11.6.4");


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
