#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K54336216.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(132570);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/17");

  script_cve_id("CVE-2019-6679");

  script_name(english:"F5 Networks BIG-IP : SCP vulnerability (K54336216)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The system does not properly enforce the access controls for the
scp.whitelist and scp.blacklist files whenpaths are symbolic links
(symlinks). This allows authenticated users with Secure Copy (SCP)
protocol access to overwrite certain configuration files that would
otherwise be restricted. (CVE-2019-6679)

Note : F5 is working to eliminate exclusionary language in our
products and documentation. For more information, refer toK34150231:
Exclusionary language in F5 products and documentation.

Impact

BIG-IP

Authenticated users with access to the Secure Copy utility ( scp ),
which is an OpenSSH tool, but without full file systemor Advanced
Shell ( bash )access, can overwrite certain configuration files.

BIG-IQ / Enterprise Manager / Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K34150231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K54336216"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K54336216."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6679");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K54336216";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["AFM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["AM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["APM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["ASM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["AVR"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["GTM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["LC"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["LTM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["PEM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0.2-14.1.2","14.0.0.5-14.0.1","13.1.1.5-13.1.3","12.1.4.1-12.1.5","11.6.4-11.6.5","11.5.9-11.5.10");
vmatrix["WAM"]["unaffected"] = make_list("15.1.0","15.0.1.1","14.1.2.3","14.0.1.1","13.1.3.2","12.1.5.1","11.6.5.1");


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
