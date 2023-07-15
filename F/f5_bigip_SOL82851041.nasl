#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K82851041.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(100006);
  script_version("3.8");
  script_cvs_date("Date: 2019/05/09  9:52:02");

  script_cve_id("CVE-2017-6137");

  script_name(english:"F5 Networks BIG-IP : TMM vulnerability (K82851041)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In F5 BIG-IP LTM, AAM, AFM, Analytics, APM, ASM, DNS, Edge Gateway,
GTM, Link Controller, PEM, PSM, WebAccelerator, and WebSafe 11.6.1
HF1, 12.0.0 HF3, 12.0.0 HF4, and 12.1.0 through 12.1.2, undisclosed
traffic patterns received while software SYN cookie protection is
engaged may cause a disruption of service to the Traffic Management
Microkernel (TMM) on specific platforms and configurations.
(CVE-2017-6137)

Impact

When software syncookie protection is activated for a virtual server
(the connection.syncookies.threshold databasevalue has been exceeded),
and the unit also has the Traffic Management Microkernel (TMM) fast
forward enabled (the tmm.ffwd.enable databasevalue is true, the
default), and TCP Segmentation Offload (TSO) is enabled(the
tm.tcpsegmentationoffload databasevalue is true, the default) a
specific sequence of packets causes TMM to generate an egress packet
with an invalid MSS. As a result, packets egressing the BIG-IP system
with an invalid MSS may be dropped by a neighboring device.
Additionally, on the 3900, 6900, 8900, 8950, 11000, and 11050
platforms this may cause the high-speed bridge (HSB) to lock up."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K82851041"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K82851041."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K82851041";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["AFM"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["AM"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["APM"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1","11.2.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["ASM"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1","11.2.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["AVR"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1","11.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.1HF1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1HF2","11.4.0-11.6.1","11.2.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["LC"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1","11.2.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["LTM"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1","11.2.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.1.0-12.1.2","12.0.0HF3-12.0.0HF4","11.6.1HF1");
vmatrix["PEM"]["unaffected"] = make_list("13.0.0","12.1.2HF1","11.6.1HF2","11.4.0-11.6.1");


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
