#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K53192206.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(101912);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2013-1752");
  script_bugtraq_id(63804);

  script_name(english:"F5 Networks BIG-IP : Python and Jython vulnerability (K53192206)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"** REJECT ** Various versions of Python do not properly restrict
readline calls, which allows remote attackers to cause a denial of
service (memory consumption) via a long string, related to (1) httplib

  - fixed in 2.7.4, 2.6.9, and 3.3.3; (2) ftplib - fixed in
    2.7.6, 2.6.9, 3.3.3; (3) imaplib - not yet fixed in
    2.7.x, fixed in 2.6.9, 3.3.3; (4) nntplib - fixed in
    2.7.6, 2.6.9, 3.3.3; (5) poplib - not yet fixed in
    2.7.x, fixed in 2.6.9, 3.3.3; and (6) smtplib - not yet
    fixed in 2.7.x, fixed in 2.6.9, not yet fixed in 3.3.x.
    NOTE: this was REJECTed because it is incompatible with
    CNT1 'Independently Fixable' in the CVE Counting
    Decisions. (CVE-2013-1752)

It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict sizes of server responses. A malicious server could cause a
client using one of the affected modules to consume an excessive
amount of memory.

Important : The status of CVE-2013-1752 was changed to REJECT by MITRE
because it did not meet the criteria for the CNT1 CVE counting rule.
However, the original vulnerabilities were addressed in the versions
indicated in the Security Advisory Status section of this article. For
more information, refer to CVE Counting Rules. This link takes you to
a resource outside of AskF5, and the third-party could remove the
document without our knowledge.

Impact

This vulnerability allows a malicious server to send extremely long
responses, causing excessive memory usage on a client in order to
cause a denial of service (DoS)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://cve.mitre.org/about/faqs.html#reject_signify_in_cve_entry"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://cve.mitre.org/cve/list_rules_and_guidance/counting_rules.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K53192206"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K53192206."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/24");
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

sol = "K53192206";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1");
vmatrix["AFM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1","11.2.1");
vmatrix["APM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1","11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1","11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1","11.2.1");
vmatrix["LC"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1","11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0","11.4.1-11.6.1");
vmatrix["PEM"]["unaffected"] = make_list("13.0.0","12.1.0-12.1.2");


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
