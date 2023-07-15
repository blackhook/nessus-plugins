#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K15217245.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(118632);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2018-2815");

  script_name(english:"F5 Networks BIG-IP : Oracle Java SE vulnerability (K15217245)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Serialization). Supported versions that
are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE
Embedded: 8u161; JRockit: R28.3.17. Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded, JRockit. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a partial denial of service (partial DOS) of Java SE, Java SE
Embedded, JRockit. Note: Applies to client and server deployment of
Java. This vulnerability can be exploited through sandboxed Java Web
Start applications and sandboxed Java applets. It can also be
exploited by supplying data to APIs in the specified Component without
using sandboxed Java Web Start applications or sandboxed Java applets,
such as through a web service. CVSS 3.0 Base Score 5.3 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
(CVE-2018-2815)

Impact

BIG-IP / BIG-IQ / F5 iWorkflow / Enterprise Manager / Traffix SDC

An attacker may cause a partial denial of service (DoS) to the
affected Java component when the vulnerability is exploited.

LineRate

There is no impact; thisF5 product is not affected by this
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K15217245"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K15217245."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2815");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K15217245";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["AFM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["AM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["APM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["ASM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["AVR"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["GTM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["LC"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["LTM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["PEM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.3","11.2.1-11.6.3");
vmatrix["WAM"]["unaffected"] = make_list("14.1.0","13.1.1.2","12.1.3.7");


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
