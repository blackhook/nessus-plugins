#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated since the vendor has determined that
# F5 Networks BIP-IP products are not affected by the referenced
# kernel vulnerability.
#
# Disabled on 2015/06/17.

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL16477.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(83037);
  script_version("2.4");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_cve_id("CVE-2010-2524");
  script_bugtraq_id(41904);

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (SOL16477)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The DNS resolution functionality in the CIFS implementation in the
Linux kernel before 2.6.35, when CONFIG_CIFS_DFS_UPCALL is enabled,
relies on a user's keyring for the dns_resolver upcall in the
cifs.upcall userspace helper, which allows local users to spoof the
results of DNS queries and perform arbitrary CIFS mounts via vectors
involving an add_key call, related to a 'cache stuffing' issue and
MS-DFS referrals."
  );
  # http://support.f5.com/kb/en-us/solutions/public/16000/400/sol16477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a729272f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:web_accelerator_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}

# Deprecated.
exit(0, "F5 Networks BIP-IP products are not affected by the referenced\nkernel vulnerability.");

include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "SOL16477";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.0.0-11.6.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("11.0.0-11.6.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.0.0-11.6.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("11.0.0-11.6.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("11.0.0-11.6.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["PSM"]["unaffected"] = make_list("11.0.0-11.4.1");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["WAM"]["unaffected"] = make_list("11.0.0-11.3.0");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.1.0-10.2.4");
vmatrix["WOM"]["unaffected"] = make_list("11.0.0-11.3.0");


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
