#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K93472064.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(127494);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2017-12190");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K93472064)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The bio_map_user_iov and bio_unmap_user functions in block/bio.c in
the Linux kernel before 4.13.8 do unbalanced refcounting when a SCSI
I/O vector has small consecutive buffers belonging to the same page.
The bio_add_pc_page function merges them into one, but the page
reference is never dropped. This causes a memory leak and possible
system lockup (exploitable against the host OS by a guest OS user, if
a SCSI disk is passed through to a virtual machine) due to an
out-of-memory condition. (CVE-2017-12190)

Impact

A locally authenticated attacker can exploit this vulnerability to
trigger an out-of-memory condition to cause a denial of service (DoS)
on the affected system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K93472064"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K93472064."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K93472064";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0-14.1.2","13.0.0-13.1.3","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["WAM"]["unaffected"] = make_list("15.0.0","14.1.2.2","13.1.3.3","12.1.5.3");


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
