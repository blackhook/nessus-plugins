##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161166);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_cve_id("CVE-2022-28818");
  script_xref(name:"IAVA", value:"2022-A-0206-S");

  script_name(english:"Adobe ColdFusion 2018.x < 2018 Update 14 / 2021.x < 2021 Update 4 XSS (APSB22-22)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2018.x update 14 or 2021.x update 4. 
It is, therefore, affected by a cross-site scripting (XSS) vulnerability due to improper validation of user-supplied 
input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to 
click a specially crafted URL, to execute arbitrary script code in a user's browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb22-22.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2018 update 14 / 2021 update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    info = check_jar_chf(name, 14);
  }
  else if (ver == '2021.0.0')
  {
    info = check_jar_chf(name, 4);
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

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);