#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K49711130.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(125481);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/25 17:12:07");

  script_cve_id("CVE-2018-5407");

  script_name(english:"F5 Networks BIG-IP : OpenSSL and Intel processor SMT side-channel vulnerability (PortSmash) (K49711130)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simultaneous Multi-threading (SMT) in processors can enable local
users to exploit software vulnerable to timing attacks via a
side-channel timing attack on 'port contention.'(CVE-2018-5407also
known as PortSmash)

Impact

The vulnerability allows an attacker who can provideand runbinary code
of their choosing on the F5platform to steal secret cryptographic
information.

Processes running on hyperthread-enabled cores are subject to a
side-channel attack by other processes running on the same core, if
their program control flow is impacted by private data. A common case
for this behavior is encryption, where the secret key can influence
program flow. While high-security contexts typically guard against
this known behavior, a flaw in OpenSSL's protection of elliptic curve
processing is vulnerable to this class of attack. Other encryption
algorithms (RSA) are not affected, so configurations that do not
install EC keys are not impacted.

Note : Hyper-threading is Intel's implementation of SMT."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K49711130"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K49711130."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");
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

sol = "K49711130";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("15.0.0","14.1.2.1");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["WAM"]["unaffected"] = make_list("15.0.0","14.1.2.1");


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
