#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153433);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id("CVE-2021-40698", "CVE-2021-40699");
  script_xref(name:"IAVA", value:"2021-A-0417-S");

  script_name(english:"Adobe ColdFusion 2018.x < 2018 Update 12 / 2021.x < 2021 Update 2 Multiple Vulnerabilities (APSB21-75)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2018.x update 12 or 2021.x update 2. It
is, therefore, affected by multiple vulnerabilities as referenced in the APSB21-75 advisory including the following: 

  - A vulnerability exists in Adobe Coldfusion due to the usage of an inherently dangerous function. An unauthenticated,
    remote attacker could exploit this to bypass security features. (CVE-2021-40698)

  - An improper access control vulnerability exists in Adobe Coldfusion. An authenticated, remote attacker could exploit 
    this to bypass security features. (CVE-2021-40699)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/coldfusion/apsb21-75.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfe2c377");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2018 update 12 / 2021 update 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40698");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include('coldfusion_win.inc');

var instances = get_coldfusion_instances();
var instance_info = [];

foreach var name (keys(instances))
{
  var info = NULL;
  var ver = instances[name];

  if (ver == '2018.0.0')
  {
    info = check_jar_chf(name, 12);
  }
  else if (ver == '2021.0.0')
  {
    info = check_jar_chf(name, 2);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Adobe ColdFusion');

var port = get_kb_item('SMB/transport');
if (!port)
  port = 445;

var report =
  '\n' + 'Nessus detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n' + 'Also note that to be fully protected the Java JDK must be patched along with applying the vendor patch.';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
