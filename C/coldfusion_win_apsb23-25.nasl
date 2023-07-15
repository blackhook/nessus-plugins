#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172595);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/24");

  script_cve_id("CVE-2023-26359", "CVE-2023-26360", "CVE-2023-26361");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/05");
  script_xref(name:"IAVA", value:"2023-A-0142");

  script_name(english:"Adobe ColdFusion < 2018.x < 2018 Update 16 / 2021.x < 2021 Update 6 Multiple Vulnerabilities (APSB23-25)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2018.x Update 16 or 2021.x Update 6.
It is, therefore, affected by multiple vulnerabilities as referenced in the APSB23-25 advisory.

  - Deserialization of Untrusted Data (CWE-502) potentially leading to Arbitrary code execution
    (CVE-2023-26359)

  - Improper Access Control (CWE-284) potentially leading to Arbitrary code execution (CVE-2023-26360)

  - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (CWE-22) potentially
    leading to Memory leak (CVE-2023-26361)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb23-25.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2018 Update 16 / 2021 Update 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26359");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 284, 502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    info = check_jar_chf(name, 16);
  }
  else if (ver == '2021.0.0')
  {
    info = check_jar_chf(name, 6);
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
