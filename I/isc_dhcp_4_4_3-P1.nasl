#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169908);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2022-2928", "CVE-2022-2929");
  script_xref(name:"IAVB", value:"2022-B-0037");

  script_name(english:"ISC DHCP < 4.4.3-P1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The DHCP server installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The ISC DHCP server installed on the remote host is prior to 4.4.3-P1. It is, therefore, vulnerable to multiple
vulnerabilities:

  - In ISC DHCP 4.4.0 up to 4.4.3, ISC DHCP 4.1-ESV-R1 up to 4.1-ESV-R16-P1, when the function
  option_code_hash_lookup() is called from add_option(), it increases the option's refcount field. However,
  there is not a corresponding call to option_dereference() to decrement the refcount field. The function
  add_option() is only used in server responses to lease query packets. Each lease query response calls this
  function for several options, so eventually, the reference counters could overflow and cause the server to
  abort. (CVE-2022-2928)

  - In ISC DHCP 1.0 up to 4.4.3, ISC DHCP 4.1-ESV-R1 up to 4.1-ESV-R16-P1 a system with access to a DHCP
  server, sending DHCP packets crafted to include fqdn labels longer than 63 bytes, could eventually cause the
  server to run out of memory. (CVE-2022-2929)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected DHCP server to version 4.4.3-P1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:dhcp");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dhcp_detect.nbin");
  script_require_keys("dhcp_server/type", "dhcp_server/version");

  exit(0);
}

var app = 'ISC DHCP';
var fix = '4.4.3-P1';

var type = get_kb_item_or_exit('dhcp_server/type');
if ('isc-dhcp' >!< type) audit(AUDIT_NOT_INST, app);

var version = get_kb_item_or_exit('dhcp_server/version');

if (version =~ "^[0-9]+\.[0-9]+$")
  audit(AUDIT_VER_NOT_GRANULAR, app, version);

if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN);

if (ver_compare(fix:fix, ver:version, regexes:{0:"-P(\d+)"}, strict:FALSE) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
