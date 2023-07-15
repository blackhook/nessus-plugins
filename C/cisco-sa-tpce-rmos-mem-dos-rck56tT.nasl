#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153944);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id("CVE-2021-34758");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy60378");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tpce-rmos-mem-dos-rck56tT");
  script_xref(name:"IAVA", value:"2021-A-0453-S");

  script_name(english:"Cisco TelePresence Collaboration Endpoint DoS (cisco-sa-tpce-rmos-mem-dos-rck56tT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Collaboration Endpoint is affected by a denial of service
(DoS) vulnerability in the memory management. This allows an authenticated, local attacker to corrupt a shared memory
segment, resulting in a DoS condition. This vulnerability is due to insufficient access controls to a shared memory
resource. An attacker could exploit this vulnerability by corrupting a shared memory segment on an affected device. A
successful exploit could allow the attacker to cause the device to reload. The device will recover from the corruption
upon reboot.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tpce-rmos-mem-dos-rck56tT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c77f501");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy60378");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy60378");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_collaboration_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");

  exit(0);
}

var app_name = 'Cisco TelePresence CE software';
var version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');
var device = get_kb_item_or_exit('Cisco/TelePresence_MCU/Device');
device = tolower(device);

if ('telepresence' >!< device && 'room' >!< device)
  audit(AUDIT_HOST_NOT, 'a vulnerable device');


var short_version = pregmatch(pattern: "^(ce)(\d+(?:\.\d+){0,2})", string:version);
var short_num, short_type;
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

var fix = '';
var bugid = 'CSCvy60378';

if (short_type != 'ce')
  audit(AUDIT_NOT_DETECT, app_name);

if (ver_compare(ver:short_num, fix:'10.7.2', strict:FALSE) < 0)
{
  var report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : ' + bugid +
           '\n';

  security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
