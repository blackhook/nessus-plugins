#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83769);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:20");

  script_cve_id("CVE-2015-0713");
  script_bugtraq_id(74638);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul55968");
  script_xref(name:"IAVA", value:"2015-A-0117");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150513-tp");

  script_name(english:"Cisco TelePresence IP VCR Command Injection Vulnerability");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, the remote Cisco TelePresence
IP VCR device contains a vulnerability in its web framework, which
can allow an authenticated, remote attacker to inject arbitrary
commands on the device with root permissions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150513-tp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f34acae");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul55968");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate software version referenced in the
vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_ip_vcr_3.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_ip_vcr_detect.nasl");
  script_require_keys("Cisco/TelePresence_IP_VCR", "Cisco/TelePresence_IP_VCR/Version", "Cisco/TelePresence_IP_VCR/Device");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device   = get_kb_item("Cisco/TelePresence_IP_VCR/Device");
version  = get_kb_item_or_exit("Cisco/TelePresence_IP_VCR/Version");

if (!empty_or_null(device) && device != UNKNOWN_VER)
  fullname = "Cisco TelePresence "+device;
else fullname = "Cisco TelePresence IP VCR";

fix = '3.0(1.27)';

if (cisco_gen_ver_compare(a:version, b:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence IP VCR software");
