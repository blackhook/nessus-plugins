#TRUSTED 8a8c35e9a9faf5240cf45a065e5e74e0639ec0db4eab8848842981770bb4d9902d0852887033e04e65a311fd00d1a65b93cebb519692136725ab3e72cf1ffec8845edb9d1ffea13714926560de3c839ef2beb3d959946cb781ade0079ea0166145c7c45bfd683f680d3c0f301a8e069f970d29a0510e64b7379073bca301aacfb55a52aa3d3b548c1f2e918c0584b93470c56ce57f2ea2eea3808f3ebe40ad378ba45c77754ccfaf6ddcdd3a9c02a5bd3de59786ee5bffdec532cc7040f5f1edce46a2b0442ecd4b4a51251e6e831fa041fe98d692bb3255da2b63b961051e6e89497825e7f0c4c742cae79e91c2ae3b371929f5734f800e705c897e969d334b06c97996d903baf58d630b0799981cfba7eee8780a11d705ffbd12e00eae74083f2de270f7d467c178529d1c2e2864862302e2f6f6755ae4d94f54375756936b011e01000c02daf1611019b9fe390a1c51d57da684f4aa42a13bf814e9311192dfe9727d5d2398c1deca809e5496fa0fa3b395dfb66679b8945b72ced1d8e4bd2352a0b1143106ff4e53baa4615164b0fc815b4604c79c603d3f4830ea414f06c1b61de28de1eba189c9171036f007502fefe4cb2fff4fadb2fdca5388d03deb7d8179ed9978856b56637d52b7457a5d6b9981e10d20463ba2dbb27e7c4c893e8575f6176eaddfa2f327a6a73bc5d552636cf7692f9e78941ed6f69b8b20a890
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130258);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12705");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq09300");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-vcs-xss");
  script_xref(name:"IAVA", value:"2019-A-0389-S");

  script_name(english:"Cisco TelePresence VCS / Expressway 12.5.x < 12.5.4 XSS");

  script_set_attribute(attribute:"synopsis", value:
"A video conferencing application running on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Video Communication Server (VCS) / Expressway running
on the remote host is 12.5.x prior to 12.5.4. It is, therefore, affected by a cross-site scripting (XSS) vulnerability
due to improper validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can
exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's
browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-vcs-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7822cce9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq09300");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence VCS / Expressway version 12.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:expressway_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

vuln_ranges = [{ 'min_ver' : '12.5', 'fix_ver' : '12.5.4' }];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq09300',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
