#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177391);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id(
    "CVE-2023-27363",
    "CVE-2023-27364",
    "CVE-2023-27365",
    "CVE-2023-27366"
  );

  script_name(english:"Foxit PhantomPDF < 10.1.12 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally known as Phantom) installed on the remote Windows
host is prior to 10.1.12. It is, therefore affected by multiple vulnerabilities:

  - Addressed a potential issue where the application could be exposed to Remote Code Execution vulnerability
    when handling certain JavaScripts. This occurs as the application fails to validate the cPath parameter in
    the exportXFAData method and is thus forced to write to the Startup folder with an .hta file that can
    execute arbitrary code after a restart. (CVE-2023-27363)

  - Addressed potential issues where the application could be exposed to Remote Code Execution vulnerability
    and crash when parsing certain XLS or DOC files. This occurs as the application opens the XLS or DOC file
    with the default permissions and allows for the execution of macros without proper restrictions or
    consents from users.  (CVE-2023-27364, CVE-2023-27365)

  - Addressed potential issues where the application could be exposed to Null Pointer Dereference or Use-
    after-Free vulnerability and crash, which could be exploited by attackers to execute remote code. This
    occurs due to the access of null pointer or freed memory without proper validation when handling certain
    JavaScripts. (CVE-2023-27366)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 10.1.12 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27365");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-27366");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.11.37866', 'fixed_version' : '10.1.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
