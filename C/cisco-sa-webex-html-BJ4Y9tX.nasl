#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139600);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_cve_id("CVE-2020-3345");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu00484");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt75607");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu06679");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-html-BJ4Y9tX");
  script_xref(name:"IAVA", value:"2020-A-0273");

  script_name(english:"Cisco Webex Meetings Scheduled Meeting Template Creation (cisco-sa-webex-smtcreate-YmuD5Sk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings is affected by a vulnerability in certain web pages due to
improper checks on parameter values within affected pages. An unauthenticated, remote attacker can exploit this, by
persuading a user to follow a crafted link that is designed to pass HTML code into an affected parameter, in order to
modify a web page in the context of a browser.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-html-BJ4Y9tX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adcf44a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt75607");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu00484");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu06679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Webex Meetings');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'fixed_version': '40.6.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

