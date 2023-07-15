#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174448);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2021-35250");

  script_name(english:"SolarWinds Serv-U 15.3 HF1");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Serv-U installed on the remote host is prior to 15.3 HF1. It is, therefore, affected by a
vulnerability as referenced in the serv-u_15_3_hf1 advisory.

  - An external security researcher reported a Directory Transversal Vulnerability in Serv-U 15.3. If
    exploited, this vulnerability could allow access to files relating to the Serv-U installation and server
    files. It is important to note no exploits of this vulnerability have been reported in the wild.
    (CVE-2021-35250)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35250
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c924ecb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U version 15.3 HF1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35250");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl");
  script_require_keys("installed_sw/Serv-U");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('ftp_func.inc');

var port = get_ftp_port(default:21);

var app_info = vcf::get_app_info(app:'Serv-U', port:port);
if (!empty_or_null(app_info.Hotfix))
  audit(AUDIT_INST_VER_NOT_VULN, app_info.app);

var constraints = [
  { 'fixed_version' : '15.3 HF1', 'equal' : '15.3' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
