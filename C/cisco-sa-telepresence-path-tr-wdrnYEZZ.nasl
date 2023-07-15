#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133530);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-3143");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs45241");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs67675");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs67680");
  script_xref(name:"CISCO-SA", value:"cisco-sa-telepresence-path-tr-wdrnYEZZ");
  script_xref(name:"IAVA", value:"2020-A-0055");

  script_name(english:"Cisco TelePresence Endpoint Software Path Traversal (cisco-sa-telepresence-path-tr-wdrnYEZZ)");
  script_summary(english:"Checks the version of Cisco TelePresence Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Codec (TC) and Collaboration Endpoint (CE) Cisco
TelePresence Software is affected by a directory traversal vulnerability. An authenticated, remote attacker can exploit
this vulnerability in order to read and write arbitrary files on the remote host.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-telepresence-path-tr-wdrnYEZZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86cc9a48");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs45241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b7ec8f6");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs67675
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?075eccb8");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs67680
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c33b8fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs67675 or CSCvs45241 and CSCvs67680");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:telepresence_ce");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app_name = 'Cisco TelePresence TC/CE software';
version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');
bugid = '';

short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

fix = '';

if (short_type == 'TC'){
    fix = '7.3.20';
    bugid = 'CSCvs67675';
}
else if (short_type == 'ce'){
  bugid = 'CSCvs45241, CSCvs67680';
  if (short_num =~ "^8\.")
    fix = '8.3.8';
  else if (short_num =~ "^9\.[0-8]($|[^0-9])")
    fix = '9.8.3';
  else if (short_num =~ "^9\.9")
    fix = '9.9.2';
}
else audit(AUDIT_NOT_DETECT, app_name);

if (!empty_or_null(fix) && ver_compare(ver:short_num, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : ' + bugid +
           '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
