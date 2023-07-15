#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132415);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2019-8848",
    "CVE-2019-15903"
  );
  script_xref(name:"APPLE-SA", value:"HT210793");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-12-06");

  script_name(english:"Apple iTunes < 12.10.3 Multiple Vulnerabilities (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.10.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT210793 advisory.

  - In libexpat before 2.2.8, crafted XML input could fool
    the parser into changing from DTD parsing to document
    parsing too early; a consecutive call to
    XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read.
    (CVE-2019-15903)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210793");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.10.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("installed_sw/iTunes DAAP");
  script_require_ports("Services/www", 3689);

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app = 'iTunes DAAP';
port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

app_info = vcf::get_app_info(app:app, port:port);
if (app_info.Type != 'Windows') audit(AUDIT_OS_NOT, 'Windows');
constraints = [{'fixed_version':'12.10.3'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);