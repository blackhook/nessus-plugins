#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131076);
  script_version("1.4");
  script_cvs_date("Date: 2020/02/06");

  script_cve_id("CVE-2019-15288");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq29901");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-telepres-roomos-privesc");

  script_name(english:"Cisco TelePresence Endpoint Software Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco TelePresence Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Codec (TC) and Collaboration Endpoint (CE) Cisco
TelePresence Software is affected by software privilege escalation vulnerability. An authenticated, remote attacker to
escalate privileges to an unrestricted user of the restricted shell. The vulnerability is due to insufficient input
validation. An attacker could exploit this vulnerability by including specific arguments when opening an SSH connection
to an affected device. A successful exploit could allow the attacker to gain unrestricted user access to the restricted
shell of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-telepres-roomos-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a19c9b87");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq29901
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42c440f9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq29901");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15288");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:telepresence_ce");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app_name = 'Cisco TelePresence TC/CE software';
version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');

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
    fix = '7.3.19';
}
else if (short_type == 'ce'){
    fix = '9.8.1';
}
else audit(AUDIT_NOT_DETECT, app_name);

if (!empty_or_null(fix) && ver_compare(ver:short_num, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : CSCvq29901' +
           '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
