#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125924);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_cve_id(
    "CVE-2018-19418",
    "CVE-2018-19444",
    "CVE-2018-19445",
    "CVE-2018-19446",
    "CVE-2018-19447",
    "CVE-2018-19448",
    "CVE-2018-19449",
    "CVE-2018-19450",
    "CVE-2018-19451",
    "CVE-2018-19452"
  );
  script_bugtraq_id(108692);

  script_name(english:"Foxit PDF SDK ActiveX < 5.5.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF SDK ActiveX application
installed on the remote Windows host is prior to 5.5.1. It is, 
therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists due to 
    a lack of security permission control which could allow
    LaunchURL actions and links to execute programs without
    a user's consent. An unauthenticated, remote 
    attacker can exploit this by convincing a user to open a
    specially crafted file, to execute arbitrary code.
    (CVE-2018-19418, CVE-2018-19445, CVE-2018-19450, CVE-2018-19451)

  - A remote code execution vulnerability exists due to 
    a lack of security permission control which could allow
    javascript and exportasFDF to write arbitrary files without
    a user's consent. An unauthenticated, remote 
    attacker can exploit this by convincing a user to open a
    specially crafted file, to execute arbitrary code.
    (CVE-2018-19446, CVE-2018-19449)

  - A remote code execution vulnerability exists due to 
    a stack buffer overflow in string1 URI parsing. 
    An unauthenticated, remote attacker can exploit this by 
    convincing a user to open a specially crafted file, to 
    execute arbitrary code. (CVE-2018-19447)

  - A remote code execution vulnerability exists due to 
    a use-after-free occurring when a javascript command
    is triggered by a mouse enter action or focus loss. 
    An unauthenticated, remote attacker can exploit this by 
    convincing a user to open a specially crafted file, to 
    execute arbitrary code. (CVE-2018-19452, CVE-2018-19444)

  - A remote code execution vulnerability exists due to 
    an uninitialized object reference as a result of a timer
    not ending when a form loses focus. An unauthenticated, 
    remote attacker can exploit this by convincing a user to 
    open a specially crafted file, to execute arbitrary code. 
    (CVE-2018-19448)");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF SDK ActiveX version 5.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19418");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_pdf_sdk_activex");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_pdf_sdk_activex_installed.nbin");
  script_require_keys("installed_sw/Foxit PDF SDK ActiveX");

  exit(0);
}

include('vcf.inc');

app = 'Foxit PDF SDK ActiveX';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{'fixed_version' : '5.5.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
