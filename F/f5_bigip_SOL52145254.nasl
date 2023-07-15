#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K52145254.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(137918);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2020-5902");
  script_xref(name:"IAVA", value:"2020-A-0283-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0122");
  script_xref(name:"CEA-ID", value:"CEA-2020-0055");

  script_name(english:"F5 Networks BIG-IP : TMUI RCE vulnerability (K52145254)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Traffic Management User Interface (TMUI), also referred to as the
Configuration utility, has a Remote Code Execution (RCE) vulnerability
in undisclosed pages.(CVE-2020-5902)

Impact

This vulnerability allows for unauthenticated attackers, or
authenticated users, with network access to the Configuration utility,
through the BIG-IP management port and/or self IPs, to execute
arbitrary system commands, create or delete files, disable services,
and/or execute arbitrary Java code. This vulnerability may result in
complete system compromise. The BIG-IP system in Appliance mode is
also vulnerable. This issue is not exposed on the data plane; only the
control plane is affected.

Note : All information present on an infiltrated system should be
considered compromised. This includes, but is not limited to, logs,
configurations, credentials, and digital certificates.

Important : If your BIG-IP system has TMUI exposed to the Internet and
it does not have a fixed version of software installed, there is a
high probability that it has been compromised and you should follow
your internal incident response procedures. Refer to the Indicatorsof
compromise section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K52145254"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K52145254."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5902");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"F5 BIG-IP Traffic Management User Interface File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP TMUI Directory Traversal and File Upload RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K52145254";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.1.0","15.0.0-15.0.1","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("16.0.0","15.1.0.4","15.0.1.4","14.1.2.6","13.1.3.4","12.1.5.2","11.6.5.2");


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
