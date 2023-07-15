#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K44551633.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(138231);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-15166");

  script_name(english:"F5 Networks BIG-IP : Multiple tcpdump vulnerabilities (K44551633)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2018-10103

tcpdump before 4.9.3 mishandles the printing of SMB data (issue 1 of
2).

CVE-2018-10105 tcpdump before 4.9.3 mishandles the printing of SMB
data (issue 2 of 2).

CVE-2018-14882 The ICMPv6 parser in tcpdump before 4.9.3 has a buffer
over-read in print-icmp6.c.

CVE-2019-15166 lmp_print_data_link_subobjs() in print-lmp.c in tcpdump
before 4.9.3 lacks certain bounds checks.

CVE-2018-16230 The BGP parser in tcpdump before 4.9.3 has a buffer
over-read in print-bgp.c:bgp_attr_print() (MP_REACH_NLRI).

CVE-2018-16300 The BGP parser in tcpdump before 4.9.3 allows stack
consumption in print-bgp.c:bgp_attr_print() because of unlimited
recursion.

CVE-2018-14881 The BGP parser in tcpdump before 4.9.3 has a buffer
over-read in print-bgp.c:bgp_capabilities_print()
(BGP_CAPCODE_RESTART).

CVE-2018-16229 The DCCP parser in tcpdump before 4.9.3 has a buffer
over-read in print-dccp.c:dccp_print_option().

CVE-2018-16228 The HNCP parser in tcpdump before 4.9.3 has a buffer
over-read in print-hncp.c:print_prefix().

CVE-2018-16227 The IEEE 802.11 parser in tcpdump before 4.9.3 has a
buffer over-read in print-802_11.c for the Mesh Flags subfield.

CVE-2018-16451 The SMB parser in tcpdump before 4.9.3 has buffer
over-reads in print-smb.c:print_trans() for \MAILSLOT\BROWSE and
\PIPE\LANMAN.

CVE-2018-16452 The SMB parser in tcpdump before 4.9.3 has stack
exhaustion in smbutil.c:smb_fdata() via recursion.

Impact

These vulnerabilities can result in denial of service (DoS) or,
potentially, execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K44551633"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K44551633."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K44551633";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("15.0.0-15.1.2","14.0.0-14.1.3","13.1.0-13.1.4","12.1.0-12.1.6","11.5.2-11.6.5");
vmatrix["WAM"]["unaffected"] = make_list("16.0.0","15.1.3","14.1.3.1","13.1.4.1");


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
