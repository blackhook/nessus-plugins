#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K61570943.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(88742);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2014-3660", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_bugtraq_id(70644);

  script_name(english:"F5 Networks BIG-IP : Multiple libXML2 vulnerabilities (K61570943)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2015-5312 The xmlStringLenDecodeEntities function in parser.c in
libxml2 before 2.9.3 does not properly prevent entity expansion, which
allows context-dependent attackers to cause a denial of service (CPU
consumption) via crafted XML data, a different vulnerability than
CVE-2014-3660.

CVE-2015-7497 Heap-based buffer overflow in the xmlDictComputeFastQKey
function in dict.c in libxml2 before 2.9.3 allows context-dependent
attackers to cause a denial of service via unspecified vectors.

CVE-2015-7498 Heap-based buffer overflow in the xmlParseXmlDecl
function in parser.c in libxml2 before 2.9.3 allows context-dependent
attackers to cause a denial of service via unspecified vectors related
to extracting errors after an encoding conversion failure.

CVE-2015-7499 Heap-based buffer overflow in the xmlGROW function in
parser.c in libxml2 before 2.9.3 allows context-dependent attackers to
obtain sensitive process memory information via unspecified vectors.

CVE-2015-7500 The xmlParseMisc function in parser.c in libxml2 before
2.9.3 allows context-dependent attackers to cause a denial of service
(out-of-bounds heap read) via unspecified vectors related to incorrect
entities boundaries and start tags.

CVE-2015-7941 libxml2 2.9.2 does not properly stop parsing invalid
input, which allows context-dependent attackers to cause a denial of
service (out-of-bounds read and libxml2 crash) via crafted XML data to
the (1) xmlParseEntityDecl or (2) xmlParseConditionalSections function
in parser.c, as demonstrated by non-terminated entities.

CVE-2015-7942 The xmlParseConditionalSections function in parser.c in
libxml2 does not properly skip intermediary entities when it stops
parsing invalid input, which allows context-dependent attackers to
cause a denial of service (out-of-bounds read and crash) via crafted
XML data, a different vulnerability than CVE-2015-7941.

CVE-2015-8241 The xmlNextChar function in libxml2 2.9.2 does not
properly check the state, which allows context-dependent attackers to
cause a denial of service (heap-based buffer over-read and application
crash) or obtain sensitive information via crafted XML data.

CVE-2015-8242 The xmlSAX2TextNode function in SAX2.c in the push
interface in the HTML parser in libxml2 before 2.9.3 allows
context-dependent attackers to cause a denial of service (stack-based
buffer over-read and application crash) or obtain sensitive
information via crafted XML data.

CVE-2015-8317 The xmlParseXMLDecl function in parser.c in libxml2
before 2.9.3 allows context-dependent attackers to obtain sensitive
information via an (1) unterminated encoding value or (2) incomplete
XML declaration in XML data, which triggers an out-of-bounds heap
read."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K61570943"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K61570943."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K61570943";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.6.0");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0-12.1.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.6.0");
vmatrix["AM"]["unaffected"] = make_list("12.0.0-12.1.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("12.0.0-12.1.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0-12.1.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.6.0");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0-12.1.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("12.0.0-12.1.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0-12.1.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.6.0");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0-12.1.0");


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
