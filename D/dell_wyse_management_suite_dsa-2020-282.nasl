##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144790);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29496", "CVE-2020-29497", "CVE-2020-29498");
  script_xref(name:"IAVB", value:"2021-B-0003-S");

  script_name(english:"Dell Wyse Management Suite < 3.1 Multiple Vulnerabilities (DSA-2020-282)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the remote Windows host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote Windows host is prior to 3.1. It is, therefore,
affected by the following vulnerabilities:

  - Dell Wyse Management Suite versions prior to 3.1 contain a stored cross-site scripting vulnerability. A
    remote authenticated malicious user with high privileges could exploit this vulnerability to store
    malicious HTML or JavaScript code while creating the Enduser. When victim users access the submitted data
    through their browsers, the malicious code gets executed by the web browser in the context of the
    vulnerable application. (CVE-2020-29496)

  - Dell Wyse Management Suite versions prior to 3.1 contain a stored cross-site scripting vulnerability. A
    remote authenticated malicious user with low privileges could exploit this vulnerability to store
    malicious HTML or JavaScript code under the device tag. When victim users access the submitted data
    through their browsers, the malicious code gets executed by the web browser in the context of the
    vulnerable application. (CVE-2020-29497)

  - Dell Wyse Management Suite versions prior to 3.1 contain an open redirect vulnerability. A remote
    unauthenticated attacker could potentially exploit this vulnerability to redirect application users to
    arbitrary web URLs by tricking the victim users to click on maliciously crafted links. The vulnerability
    could be used to conduct phishing attacks that cause users to unknowingly visit malicious sites.
    (CVE-2020-29498)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-ie/000180983/dsa-2020-282");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite 3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Dell Wyse Management Suite', win_local:TRUE);

constraints = [
  { 'fixed_version' : '3.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
