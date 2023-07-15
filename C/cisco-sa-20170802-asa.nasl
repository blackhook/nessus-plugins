#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102497);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd82064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170802-asa");

  script_name(english:"Cisco Adaptive Security Appliance Authenticated Cross-Site Scripting Vulnerability (CSCvd82064)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a vulnerability in the web-based management
interface of Cisco Adaptive Security Appliance (ASA) could allow 
an authenticated, remote attacker to conduct a cross-site scripting
(XSS) attack against a user of the web-based management interface of
an affected device.

The vulnerability is due to insufficient validation of user-supplied
input by the web-based management interface of an affected device.
An attacker could exploit this vulnerability by persuading a user of
the interface to click a crafted link. A successful exploit could
allow the attacker to execute arbitrary script code in the context of
the interface or allow the attacker to access sensitive browser-based
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ae34eea");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170802-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])')
  audit(AUDIT_HOST_NOT, 'ASA 5500-X');

cbi = 'CSCvd82064';
flag = 0;

if (version == "9.5(1)") flag++;

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_NOTE,
    version  : version,
    bug_id   : cbi,
    fix      : "See advisory",
    xss      : TRUE
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
