##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142824);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/07");

  script_cve_id("CVE-2020-26086");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv34713");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tele-info-DrEGLpDQ");
  script_xref(name:"IAVA", value:"2020-A-0528-S");

  script_name(english:"Cisco TelePresence Collaboration Endpoint Software Information Disclosure (cisco-sa-tele-info-DrEGLpDQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Collaboration Endpoint Software is affected by a
vulnerability in the video endpoint API (xAPI). An authenticated, remote attacker can exploit this, by accessing
information that should not be accessible to users with low privileges, in order to gain access to sensitive
information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tele-info-DrEGLpDQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4e6b727");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv34713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv34713");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26086");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_collaboration_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");

  exit(0);
}
include('misc_func.inc');

app_name = 'Cisco TelePresence TC/CE software';
version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');
device = get_kb_item_or_exit('Cisco/TelePresence_MCU/Device');
device = tolower(device);

if ('room' >!< device && 'board' >!< device && 'desk pro' >!< device)
  audit(AUDIT_HOST_NOT, 'a vulnerable device');


short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

fix = '';
bugid = 'CSCvv34713';

if (short_type != 'ce')
  audit(AUDIT_NOT_DETECT, app_name);

if (ver_compare(ver:short_num, fix:'9.14.3', strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : ' + bugid +
           '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
