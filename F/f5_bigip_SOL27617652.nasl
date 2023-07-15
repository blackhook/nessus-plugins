#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K27617652.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(119895);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2018-15335");

  script_name(english:"F5 Networks BIG-IP : BIG-IP APM OAuth failure response message vulnerability (K27617652)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When APM is deployed as an OAuth Resource Server, APM becomes a client
application to an external OAuth authorization server. In certain
cases when communication between the BIG-IP APM and the OAuth
authorization server is lost, APM may not display the intended message
in the failure response. (CVE-2018-15335)

Impact

BIG-IP APM

A vulnerable BIG-IP APM system may not include the intended diagnostic
content in its failure response.

BIG-IP (LTM, AAM, AFM, Analytics, ASM, DNS, Edge Gateway, FPS, GTM,
Link Controller, PEM, WebAccelerator), BIG-IQ, Enterprise Manager, F5
iWorkflow, and Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability.."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K27617652"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K27617652."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K27617652";
vmatrix = make_array();

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0-13.1.1");
vmatrix["APM"]["unaffected"] = make_list("14.0.0");


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
  else audit(AUDIT_HOST_NOT, "running the affected module APM");
}
