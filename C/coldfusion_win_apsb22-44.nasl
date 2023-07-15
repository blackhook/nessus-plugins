#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166095);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2022-35690",
    "CVE-2022-35710",
    "CVE-2022-35711",
    "CVE-2022-35712",
    "CVE-2022-38418",
    "CVE-2022-38419",
    "CVE-2022-38420",
    "CVE-2022-38421",
    "CVE-2022-38422",
    "CVE-2022-38423",
    "CVE-2022-38424",
    "CVE-2022-42340",
    "CVE-2022-42341"
  );
  script_xref(name:"IAVA", value:"2022-A-0416-S");

  script_name(english:"Adobe ColdFusion < 2018.x < 2018u15 / 2021.x < 2021u5 Multiple Vulnerabilities (APSB22-44)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2018.x update 15 or 2021.x update 5. It
is, therefore, affected by multiple vulnerabilities as referenced in the APSB22-44 advisory.

  - Stack-based Buffer Overflow (CWE-121) potentially leading to Arbitrary code execution (CVE-2022-35690,
    CVE-2022-35710)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2022-35711,
    CVE-2022-35712)

  - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') potentially leading
    to Arbitrary code execution (CVE-2022-38418, CVE-2022-38421)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb22-44.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2018 update 15 / 2021 update 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 121, 122, 200, 611, 798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    info = check_jar_chf(name, 15);
  }
  else if (ver == '2021.0.0')
  {
    info = check_jar_chf(name, 5);
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