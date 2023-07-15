#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K34035645.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(118655);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2018-7320", "CVE-2018-7321", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7326", "CVE-2018-7327", "CVE-2018-7328", "CVE-2018-7329", "CVE-2018-7330", "CVE-2018-7331", "CVE-2018-7332", "CVE-2018-7333", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7417", "CVE-2018-7418", "CVE-2018-7419", "CVE-2018-7420", "CVE-2018-7421");

  script_name(english:"F5 Networks BIG-IP : Multiple Wireshark vulnerabilities (K34035645)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2018-7320

In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12, the SIGCOMP protocol
dissector could crash. This was addressed in
epan/dissectors/packet-sigcomp.c by validating operand offsets.

CVE-2018-7321 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-thrift.c had a large loop that was addressed by
not proceeding with dissection after encountering an unexpected type.

CVE-2018-7322 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-dcm.c had an infinite loop that was addressed
by checking for integer wraparound.

CVE-2018-7323 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-wccp.c had a large loop that was addressed by
ensuring that a calculated length was monotonically increasing.

CVE-2018-7324 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-sccp.c had an infinite loop that was addressed
by using a correct integer data type.

CVE-2018-7325 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-rpki-rtr.c had an infinite loop that was
addressed by validating a length field.

CVE-2018-7326 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-lltd.c had an infinite loop that was addressed
by using a correct integer data type.

CVE-2018-7327 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-openflow_v6.c had an infinite loop that was
addressed by validating property lengths.

CVE-2018-7328 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-usb.c had an infinite loop that was addressed
by rejecting short frame header lengths.

CVE-2018-7329 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-s7comm.c had an infinite loop that was
addressed by correcting off-by-one errors.

CVE-2018-7330 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-thread.c had an infinite loop that was
addressed by using a correct integer data type.

CVE-2018-7331 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-ber.c had an infinite loop that was addressed
by validating a length.

CVE-2018-7332 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-reload.c had an infinite loop that was
addressed by validating a length.

CVE-2018-7333 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12,
epan/dissectors/packet-rpcrdma.c had an infinite loop that was
addressed by validating a chunk size.

CVE-2018-7334 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12, the
UMTS MAC dissector could crash. This was addressed in
epan/dissectors/packet-umts_mac.c by rejecting a certain reserved
value.

CVE-2018-7335 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12, the
IEEE 802.11 dissector could crash. This was addressed in
epan/crypt/airpdcap.c by rejecting lengths that are too small.

CVE-2018-7336 In Wireshark 2.4.0 to 2.4.4 and 2.2.0 to 2.2.12, the FCP
protocol dissector could crash. This was addressed in
epan/dissectors/packet-fcp.c by checking for a NULL pointer.

CVE-2018-7337 In Wireshark 2.4.0 to 2.4.4, the DOCSIS protocol
dissector could crash. This was addressed in
plugins/docsis/packet-docsis.c by removing the recursive algorithm
that had been used for concatenated PDUs.

CVE-2018-7417 In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the
IPMI dissector could crash. This was addressed in
epan/dissectors/packet-ipmi-picmg.c by adding support for crafted
packets that lack an IPMI header.

CVE-2018-7418 In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the
SIGCOMP dissector could crash. This was addressed in
epan/dissectors/packet-sigcomp.c by correcting the extraction of the
length value.

CVE-2018-7419 In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the
NBAP dissector could crash. This was addressed in
epan/dissectors/asn1/nbap/nbap.cnf by ensuring DCH ID initialization.

CVE-2018-7420 In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the
pcapng file parser could crash. This was addressed in wiretap/pcapng.c
by adding a block-size check for sysdig event blocks.

CVE-2018-7421 In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the DMP
dissector could go into an infinite loop. This was addressed in
epan/dissectors/packet-dmp.c by correctly supporting a bounded number
of Security Categories for a DMP Security Classification.

Impact

BIG-IP

A remote attacker can transmit crafted packets while a BIG-IP
administrator account runs the tshark utility with the affected
protocol parsers via Advanced Shell ( bash ). This causes the tshark
utility to stop responding and may allow remote code execution from
the BIG-IP administrator account.

BIG-IQ, Enterprise Manager, F5 iWorkflow, ARX, LineRate, and Traffix
SDC

There is no impact; these F5 products are not affected by this
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K34035645"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K34035645."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7421");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/22");
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

sol = "K34035645";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["AFM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["AM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["APM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["ASM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["AVR"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["GTM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["LC"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["LTM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["PEM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.3");
vmatrix["WAM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2","12.1.3.6");


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
