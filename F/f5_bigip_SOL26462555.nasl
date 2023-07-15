#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K26462555.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(132561);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/02");

  script_cve_id("CVE-2019-6665");

  script_name(english:"F5 Networks BIG-IP : BIG-IP ASM and BIG-IQ/Enterprise Manager/F5 iWorkflow device authentication and trust vulnerability (K26462555)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An attacker with access to the device communication between the BIG-IP
ASM Central Policy Builder and the BIG-IQ/Enterprise Manager/F5
iWorkflow will be able to set up the proxy the same way and intercept
the traffic. (CVE-2019-6665)

Impact

BIG-IP ASM / BIG-IQ / Enterprise Manager / F5 iWorkflow

With access to theauthentication token, the attacker will be able to
impersonate the BIG-IP ASM Central Policy Builder and send corrupted
or incorrect suggestion data to the BIG-IQ/Enterprise Manager/F5
iWorkflow. This may lead to incorrect policy building suggestions or a
partial denial-of-service (DoS).

BIG-IP (LTM, AAM, AFM, Analytics, APM, DNS, Edge Gateway, GTM,Link
Controller, PEM, WebAccelerator, WebSafe) / Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K26462555"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K26462555."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/26");
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

sol = "K26462555";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0-15.0.1","14.1.0-14.1.2","14.0.0-14.0.1","13.1.0-13.1.3.1");
vmatrix["ASM"]["unaffected"] = make_list("15.0.1.1","14.1.2.1","14.0.1.1","13.1.3.2");


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
  else audit(AUDIT_HOST_NOT, "running the affected module ASM");
}
