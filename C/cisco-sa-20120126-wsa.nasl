#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79273);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2011-4862");
  script_bugtraq_id(51182);
  script_xref(name:"EDB-ID", value:"18280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo90523");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120126-ironport");

  script_name(english:"Cisco Web Security Appliance Telnet Remote Code Execution (cisco-sa-20120126-ironport)");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of AsyncOS running
on the remote Cisco Web Security Appliance (WSA) is affected by a
remote code execution vulnerability due to a buffer overflow condition
in the telnet component.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120126-ironport
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6a6592a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo90523");
  script_set_attribute(attribute:"see_also", value:"https://www.freebsd.org/security/advisories/FreeBSD-SA-11:08.telnetd.asc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20120126-ironport.

Alternatively, as a workaround, the vendor notes that Telnet services
can be disabled on the device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

# If not paranoid, check if telnet is detected first.
# get_service() may fork; don't use.
if (report_paranoia < 2) get_kb_list_or_exit("Services/telnet");

# Affected/Fixed Cisco AsyncOS Software for Cisco WSA :
# 7.1 and prior - Not Available - Upgrade to 7.7 or later
# 7.5 -  Not Available - Upgrade to 7.7 or later
# 7.7 - 7.7.0-757
# 8.0 - 8.0.6-073
# 8.1 - 8.1.0-235
if (
  ver =~ "^[0-6]\."   ||
  ver =~ "^7\.[01]\." ||
  ver =~ "^7\.5\."    ||
  ver =~ "^7\.7\."
)
  display_fix = '7.7.0-757';
else if (ver =~ "^8\.0\.")
  display_fix = '8.0.6-073';
else if (ver =~ "^8\.1\.")
  display_fix = '8.1.0-235';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + 
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
