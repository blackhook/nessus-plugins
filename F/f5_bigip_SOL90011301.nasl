#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K90011301.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(154888);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/03");

  script_cve_id("CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3863");

  script_name(english:"F5 Networks BIG-IP : libssh2 vulnerabilities (K90011301)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2019-3856

An integer overflow flaw, which could lead to an out of bounds write,
was discovered in libssh2 before 1.8.1 in the way keyboard prompt
requests are parsed. A remote attacker who compromises a SSH server
may be able to execute code on the client system when a user connects
to the server.

CVE-2019-3857 An integer overflow flaw which could lead to an out of
bounds write was discovered in libssh2 before 1.8.1 in the way
SSH_MSG_CHANNEL_REQUEST packets with an exit signal are parsed. A
remote attacker who compromises a SSH server may be able to execute
code on the client system when a user connects to the server.

CVE-2019-3863 A flaw was found in libssh2 before 1.8.1. A server could
send a multiple keyboard interactive response messages whose total
length are greater than unsigned char max characters. This value is
used as an index to copy memory causing in an out of bounds memory
write error.

Impact

For CVE-2019-3856 and CVE-2019-3857, a remote attacker may be able to
execute code on the client system when a user connects to the server.

For CVE-2019-3863, an attacker may be able to initiate a response from
the server in which the message length causes an out-of-bounds memory
write."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K90011301"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K90011301."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3863");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/04");
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

sol = "K90011301";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["AFM"]["unaffected"] = make_list("16.1.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["AM"]["unaffected"] = make_list("16.1.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["APM"]["unaffected"] = make_list("16.1.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["ASM"]["unaffected"] = make_list("16.1.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["AVR"]["unaffected"] = make_list("16.1.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["GTM"]["unaffected"] = make_list("16.1.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["LC"]["unaffected"] = make_list("16.1.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
vmatrix["LTM"]["unaffected"] = make_list("16.1.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5","12.1.0-12.1.6");
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
