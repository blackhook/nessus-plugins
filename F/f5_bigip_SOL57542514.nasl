#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K57542514.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(151496);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/21");

  script_cve_id("CVE-2019-10160", "CVE-2019-9636");

  script_name(english:"F5 Networks BIG-IP : Python vulnerabilities (K57542514)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Python 2.7.x through 2.7.16 and 3.x through 3.7.2 is affected by:
Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization. The impact is: Information disclosure
(credentials, cookies, etc. that are cached against a given hostname).
The components are: urllib.parse.urlsplit, urllib.parse.urlparse. The
attack vector is: A specially crafted URL could be incorrectly parsed
to locate cookies or authentication data and send that information to
a different host than when parsed correctly. This is fixed in:
v2.7.17, v2.7.17rc1, v2.7.18, v2.7.18rc1; v3.5.10, v3.5.10rc1, v3.5.7,
v3.5.8, v3.5.8rc1, v3.5.8rc2, v3.5.9; v3.6.10, v3.6.10rc1, v3.6.11,
v3.6.11rc1, v3.6.12, v3.6.9, v3.6.9rc1; v3.7.3, v3.7.3rc1, v3.7.4,
v3.7.4rc1, v3.7.4rc2, v3.7.5, v3.7.5rc1, v3.7.6, v3.7.6rc1, v3.7.7,
v3.7.7rc1, v3.7.8, v3.7.8rc1, v3.7.9. (CVE-2019-9636)

A security regression of CVE-2019-9636 was discovered in python since
commit d537ab0ff9767ef024f26246899728f0116b1ec3 affecting versions
2.7, 3.5, 3.6, 3.7 and from v3.8.0a4 through v3.8.0b1, which still
allows an attacker to exploit CVE-2019-9636 by abusing the user and
password parts of a URL. When an application parses user-supplied URLs
to store cookies, authentication credentials, or other kind of
information, it is possible for an attacker to provide specially
crafted URLs to make the application locate host-related information
(e.g. cookies, authentication data) and send them to a different host
than where it should, unlike if the URLs had been correctly parsed.
The result of an attack may vary based on the
application.(CVE-2019-10160)

Impact

A remote attacker may be able to use a specially crafted URL to locate
cookies or authentication data and send that information to a
different host than when parsed correctly.

BIG-IP Extended Application Verification (EAV) monitors using the
Python urlsplit() function with URLs from an untrusted source may be
impacted by this vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K57542514"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K57542514."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/12");
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

sol = "K57542514";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("16.1.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("16.1.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("16.1.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("16.1.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("16.1.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("16.1.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("16.1.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("16.1.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.5","14.1.0-14.1.4","13.1.0-13.1.5","12.1.0-12.1.6","11.6.1-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("16.1.0");


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
