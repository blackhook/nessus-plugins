#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130624);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/15");

  script_cve_id("CVE-2019-15962");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq47315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-tele-ce-filewrite");

  script_name(english:"Cisco TelePresence Collaboration Endpoint Software Arbitrary File Write (cisco-sa-20191016-tele-ce-filewrite)");
  script_summary(english:"Checks the version of Cisco TelePresence Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Collaboration Endpoint (CE) Cisco TelePresence Software
is affected by a vulnerability due to improper permission assignment. An authenticated, local attacker can exploit this
by logging in as the remotesupport user to write files to the /root directory of an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-tele-ce-filewrite
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17ced5d0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq47315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq47315.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:telepresence_ce");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# The advisory applies only to models of Webex Board and Webex Room devices, however after searching online it's
# still unclear what the model check should look like, so this whole plugin is paranoid.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_name = 'Cisco TelePresence TC/CE software';
device = get_kb_item_or_exit('Cisco/TelePresence_MCU/Device');
version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');

short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
# The FTP banner part of the detection will set a version without a leading TC or ce
ftp_version = pregmatch(pattern: "^[0-9.()]+", string:version);

if (isnull(short_version) && isnull(ftp_version))
  audit(AUDIT_NOT_DETECT, app_name);

if (!isnull(short_version))
{
  short_type = short_version[1];
  short_num = short_version[2];
  if (short_type != 'ce')
    audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
}
else
  short_num = ftp_version;

fix = '9.8.1';

if (!empty_or_null(fix) && ver_compare(ver:short_num, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : CSCvq47315' +
           '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
