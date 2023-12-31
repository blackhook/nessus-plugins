#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K17061.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(88811);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605");
  script_bugtraq_id(74413, 75233, 75241, 75246, 75249, 75251, 75252);

  script_name(english:"F5 Networks BIG-IP : Multiple PHP vulnerabilities (K17061)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2015-4599 The SoapFault::__toString method in ext/soap/soap.c in
PHP before 5.4.40, 5.5.x before 5.5.24, and 5.6.x before 5.6.8 allows
remote attackers to obtain sensitive information, cause a denial of
service (application crash), or possibly execute arbitrary code via an
unexpected data type, related to a 'type confusion' issue.

CVE-2015-4600 The SoapClient implementation in PHP before 5.4.40,
5.5.x before 5.5.24, and 5.6.x before 5.6.8 allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via an unexpected data type, related to 'type
confusion' issues in the (1) SoapClient::__getLastRequest, (2)
SoapClient::__getLastResponse, (3)
SoapClient::__getLastRequestHeaders, (4)
SoapClient::__getLastResponseHeaders, (5) SoapClient::__getCookies,
and (6) SoapClient::__setCookie methods.

CVE-2015-4601 PHP before 5.6.7 might allow remote attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via an unexpected data type, related to 'type confusion' issues
in (1) ext/soap/php_encoding.c, (2) ext/soap/php_http.c, and (3)
ext/soap/soap.c, a different issue than CVE-2015-4600.

CVE-2015-4602 The __PHP_Incomplete_Class function in
ext/standard/incomplete_class.c in PHP before 5.4.40, 5.5.x before
5.5.24, and 5.6.x before 5.6.8 allows remote attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via an unexpected data type, related to a 'type confusion' issue.

CVE-2015-4603 The exception::getTraceAsString function in
Zend/zend_exceptions.c in PHP before 5.4.40, 5.5.x before 5.5.24, and
5.6.x before 5.6.8 allows remote attackers to execute arbitrary code
via an unexpected data type, related to a 'type confusion' issue.

CVE-2015-4604 The mget function in softmagic.c in file 5.x, as used in
the Fileinfo component in PHP before 5.4.40, 5.5.x before 5.5.24, and
5.6.x before 5.6.8, does not properly maintain a certain pointer
relationship, which allows remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via a
crafted string that is mishandled by a 'Python script text executable'
rule.

CVE-2015-4605 The mcopy function in softmagic.c in file 5.x, as used
in the Fileinfo component in PHP before 5.4.40, 5.5.x before 5.5.24,
and 5.6.x before 5.6.8, does not properly restrict a certain offset
value, which allows remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
string that is mishandled by a 'Python script text executable' rule."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K17061"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K17061."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K17061";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.6.0","11.3.0-11.5.3");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.6.0","11.4.0-11.5.3");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.3","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.3","10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.3");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1","11.5.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.3","10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.3","10.1.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.6.0","11.3.0-11.5.3");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.1","11.5.4");


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
