#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102779);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2017-6768");
  script_bugtraq_id(100363);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc96087");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170816-apic2");

  script_name(english:"Cisco Application Policy Infrastructure Controller Custom Binary Privilege Escalation Vulnerability");
  script_summary(english:"Checks the Cisco Application Policy Infrastructure Controller (APIC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Application
Policy Infrastructure Controller (APIC) is affected by one or more
vulnerabilities. Please see the included Cisco BIDs and the Cisco
Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170816-apic2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8404bf8e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc96087");

  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc96087.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6768");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("cisco_func.inc");

app = "Cisco APIC Software";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = install['version'];
vuln = FALSE;

if (
  version == "1.1(1j)" ||
  version == "1.1(0.920a)" ||
  version == "1.1(3f)" ||
  version == "1.3(2f)" ||
  version == "1.3(1)" ||
  version == "1.3(2)" ||
  version == "1.2" ||
  version == "1.2.2" ||
  version == "1.2(3)" ||
  version == "1.2(2)" ||
  version == "2.0" ||
  version == "2.0(1)"
)  vuln = TRUE;

if (vuln)
{
  report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + "See advisory" +
  '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);


