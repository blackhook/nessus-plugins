#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103569);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_name(english:"Windows Defender Antimalware/Antivirus Signature Definition Check");
  script_summary(english:"The malware definition in Windows Defender are continuously updated and should not be more than 1 day old");
  script_set_attribute(attribute:"synopsis", value:"Windows Defender 
AntiMalware / AntiVirus Signatures are continuously not and should not be more than 1 day old");
  script_set_attribute(attribute:"description", value:
"Windows Defender has an AntiMalware/AntiVirus signature that gets
updated continuously. The signature definition has not been updated 
in more than 1 day.");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/wdsi/definitions");
  script_set_attribute(attribute:"solution", value:"Trigger an update manually and/or enable auto-updates.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_defender_win_installed.nbin");
  script_require_keys("installed_sw/Windows Defender");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('antivirus.inc');

include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("kerberos_func.inc");
include("datetime.inc");
include("antivirus.inc");

app_info = vcf::get_app_info(app:'Windows Defender', win_local:TRUE);

# Check if disabled
if (!isnull(app_info['Disabled']))
  exit(0,'Windows Defender is disabled.');

# If both null then defender is not installed
if (isnull(app_info['Malware Signature Timestamp']) && isnull(app_info['Malware Signature Version']))
  exit(0, 'Unable to retrive a signature timestamp and version.');

# Lets build the report
report += '\n  Malware Signature Timestamp : ' + app_info['Malware Signature Timestamp'];
report += '\n  Malware Signature Version   : ' + app_info['Malware Signature Version'];
report += '\n';

# if defintions are out of delay range, flag
if (check_av_def_date(date:app_info['epoch_time']))
  security_report_v4(port:app_info.port, severity:SECURITY_HOLE, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Windows Defender');
