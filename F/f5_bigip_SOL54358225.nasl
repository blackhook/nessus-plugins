#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K54358225.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(118611);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/09");

  script_cve_id("CVE-2017-0301");

  script_name(english:"F5 Networks BIG-IP : BIG-IP APM Portal Access vulnerability (K54358225)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In F5 BIG-IP APM software versions 11.5.0, 11.5.1, 11.5.2, 11.5.3,
11.5.4, 11.6.0, 11.6.1, 12.0.0, 12.1.0, 12.1.1 and 12.1.2 BIG-IP APM
portal access requests do not return the intended resources in some
cases. This may allow access to internal BIG-IP APM resources, however
the application resources and backend servers are unaffected.
(CVE-2017-0301)

Impact

When BIG-IP APM is licensed and provisioned, this vulnerability may
allow access to internal BIG-IP APM resources. The application
resources and backend servers are unaffected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K54358225"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K54358225."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");
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

sol = "K54358225";
vmatrix = make_array();

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0-12.1.2","11.6.0-11.6.1","11.5.0-11.5.4");
vmatrix["APM"]["unaffected"] = make_list("12.1.3","11.6.2","11.5.5");


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
