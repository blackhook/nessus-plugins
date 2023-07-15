#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149849);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/07");

  script_cve_id("CVE-2020-26068");
  script_xref(name:"IAVA", value:"2020-A-0528-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu31646");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tp-uathracc-jWNESUfM");

  script_name(english:"Cisco Telepresence CE Software Unauthorized Token Generation (cisco-sa-tp-uathracc-jWNESUfM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence CE Software is affected by a vulnerability. A vulnerability
in the xAPI service of Cisco Telepresence CE Software and Cisco RoomOS Software could allow an authenticated, remote
attacker to generate an access token for an affected device. The vulnerability is due to insufficient access
authorization. An attacker could exploit this vulnerability by using the xAPI service to generate a specific token. A
successful exploit could allow the attacker to use the generated token to enable experimental features on the device
that should not be available to users.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tp-uathracc-jWNESUfM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5ffd57b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu31646");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu31646");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(639);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:telepresence_ce");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Version");

  exit(0);
}


var app_name = 'Cisco TelePresence TC/CE software';
var version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');

var short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  var short_type = short_version[1];
  var short_num = short_version[2];
}

var fix = '';
var bugid = 'CSCvu31646';

if (short_type == 'ce'){
  if (short_num =~ "^9\.10\.")
    fix = '9.10.3';
  else if (short_num =~ "^9\.12\.")
    fix = '9.12.4';
}
else audit(AUDIT_NOT_DETECT, app_name);

if (!empty_or_null(fix) && ver_compare(ver:short_num, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : ' + bugid +
           '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

