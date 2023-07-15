#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K14363514.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(105333);
  script_version("3.3");
  script_cvs_date("Date: 2019/01/04 10:03:41");

  script_cve_id("CVE-2017-3736");

  script_name(english:"F5 Networks BIG-IP : OpenSSL vulnerability (K14363514)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is a carry propagating bug in the x86_64 Montgomery squaring
procedure in OpenSSL before 1.0.2m and 1.1.0 before 1.1.0g. No EC
algorithms are affected. Analysis suggests that attacks against RSA
and DSA as a result of this defect would be very difficult to perform
and are not believed likely. Attacks against DH are considered just
feasible (although very difficult) because most of the work necessary
to deduce information about a private key may be performed offline.
The amount of resources required for such an attack would be very
significant and likely only accessible to a limited number of
attackers. An attacker would additionally need online access to an
unpatched system using the target private key in a scenario with
persistent DH parameters and a private key that is shared between
multiple clients. This only affects processors that support the BMI1,
BMI2 and ADX extensions like Intel Broadwell (5th generation) and
later or AMD Ryzen. (CVE-2017-3736)

Impact

For configurations using iRulesLX, the connection between the iAppsLX
administrative interface and clients is vulnerable to high-complexity
attacks on DH parameters used in the HTTPS session. This vulnerability
applies to the following platforms :

BIG-IP I2800, I2600 (C117)

BIG-IP I4800, I4600 (C115)

BIG-IP I5800, I5600 (C119)

BIG-IP I7800, I7600 (C118)

BIG-IP I10800, I10600 (C116)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K14363514"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K14363514."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K14363514";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["AFM"]["unaffected"] = make_list("14.1.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["AM"]["unaffected"] = make_list("14.1.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["APM"]["unaffected"] = make_list("14.1.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["ASM"]["unaffected"] = make_list("14.1.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["AVR"]["unaffected"] = make_list("14.1.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["GTM"]["unaffected"] = make_list("14.1.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["LC"]["unaffected"] = make_list("14.1.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["LTM"]["unaffected"] = make_list("14.1.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["PEM"]["unaffected"] = make_list("14.1.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3");
vmatrix["WAM"]["unaffected"] = make_list("14.1.0");


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
