#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K64571774.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(143103);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id("CVE-2020-5947");
  script_xref(name:"IAVA", value:"2020-A-0573");

  script_name(english:"F5 Networks BIG-IP : BIG-IP virtual server TCP sequence numbers vulnerability (K64571774)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"On specific BIG-IP platforms, attackersmay be able to obtain TCP
sequence numbers from the BIG-IP system that can be reused in future
connections with the same source and destination port and IP
numbers.(CVE-2020-5947)

Impact

Attackers may be able to spoof TCP packets to be used by a future
connection, resulting in a TCP sequence prediction attack.

This issue affects platforms that do not have hardware-based SYN
cookie capabilities. The following BIG-IP platforms do not contain the
high speed bus (HSBe2) chip and do not have hardware-based SYN cookie
capability, and are therefore vulnerable :

BIG-IP 2000 series (C112)

BIG-IP 4000 series (C113)

BIG-IP i2000 series (C117)

BIG-IP i4000 series (C115)

BIG-IP Virtual Edition (VE)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K64571774"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K64571774."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5947");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K64571774";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["AFM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["AM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["APM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["ASM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["AVR"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["GTM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["LC"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["LTM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("16.0.0","15.0.0-15.1.1");
vmatrix["PEM"]["unaffected"] = make_list("16.1.0","16.0.1","15.1.2");


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
