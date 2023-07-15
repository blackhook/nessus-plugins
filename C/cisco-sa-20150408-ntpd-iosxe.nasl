#TRUSTED 002f4a2661bad06c33c4bba72add6e517d0055c85bae9b7917133dfffe07630d274b3e749648faac1e8de4e85b2ca154ce14b4c6e9a07685c66133fa32c654fd655a65085b092e80852ca210e091b7ee23677e3cd8b9861edf5a0a19ffaa9691923e07eecfefa8270d5563dcab942ae468a2b65f3489012ea3fcc8207fbc50bffc320ff97b1b18f4837ff7db45833fe1c98803b9dc415b741605cddd7aed445fac6e236945ffa5dde3cdce8f11af8d71372b2e4b3cf1be5f2585b505e61e07931bd2daafd33dedfc9abf0523afb73f8907385ca3816b375a64c014d49960c370a3393e8a376df46d212d639818630f003f6439d5bc8ed8425b677887e3487e32226709b0836b085bf4c636076932b0a292efa8a168b711eb27f17021e9d4c79abaeefccb5b7ca44a4d4b0872450971223cfde1aa27566a700fbeb5e38b9b8b8ba4c3fc0c2f4462d7850f96523570a6ca96f3c622c7d424bb843548bfb680cec7b4c6bf5e83c003b51cc1cc16ac4040988a6f8512a02ddcff513f2873cafeab29838009a4f19082831cde39a68ae7e197d0013e6f9217352e645267c794b8ca606ded7995b3f0848850521b2ddbc282b1067a2f573b893c5af74ea689fad51ea61c413395a056becf5d87cf25345690d3b5ea34401999a5538c542a40132a81a9d5d58274033ddfb97b0e789dd19b3273d47ff51eadda54718eee700f87911e76
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108955);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2015-1798", "CVE-2015-1799");
  script_bugtraq_id(73950, 73951);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut77619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150408-ntpd");

  script_name(english:"Cisco IOS XE Software Multiple Vulnerabilities in ntpd (cisco-sa-20150408-ntpd)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150408-ntpd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aaf9b51");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut77619");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCut77619.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1799");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "2.3.0",
  "2.3.0t",
  "2.3.1t",
  "2.3.2",
  "2.3.1",
  "2.4.0",
  "2.4.1",
  "2.4.2",
  "2.4.3",
  "2.1.0",
  "2.1.1",
  "2.1.2",
  "2.2.1",
  "2.2.2",
  "2.2.3",
  "2.2.0",
  "2.5.0",
  "2.5.1",
  "2.5.2",
  "2.6.0",
  "2.6.1",
  "2.6.2",
  "3.1.0S",
  "3.1.1S",
  "3.1.2S",
  "3.1.3S",
  "3.1.4S",
  "3.1.5S",
  "3.1.6S",
  "3.1.4aS",
  "3.1.3aS",
  "3.2.0S",
  "3.2.1S",
  "3.2.2S",
  "3.2.3S",
  "3.3.0S",
  "3.3.1S",
  "3.3.2S",
  "3.4.0S",
  "3.4.1S",
  "3.4.2S",
  "3.4.3S",
  "3.4.4S",
  "3.4.5S",
  "3.4.6S",
  "3.4.0aS",
  "3.1.1SG",
  "3.1.0SG",
  "3.2.0SG",
  "3.2.1SG",
  "3.2.2SG",
  "3.2.3SG",
  "3.2.4SG",
  "3.2.5SG",
  "3.2.6SG",
  "3.2.7SG",
  "3.2.8SG",
  "3.2.9SG",
  "3.2.10SG",
  "3.2.11SG",
  "3.5.0S",
  "3.5.1S",
  "3.5.2S",
  "3.6.0S",
  "3.6.1S",
  "3.6.2S",
  "3.7.0S",
  "3.7.1S",
  "3.7.2S",
  "3.7.3S",
  "3.7.4S",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.7.4aS",
  "3.7.2tS",
  "3.2.0XO",
  "3.2.1XO",
  "3.3.0SG",
  "3.3.2SG",
  "3.3.1SG",
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.1S",
  "3.9.0S",
  "3.9.2S",
  "3.9.1aS",
  "3.9.0aS",
  "3.2.0SE",
  "3.2.1SE",
  "3.2.2SE",
  "3.2.3SE",
  "3.3.0SE",
  "3.3.1SE",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7aSG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.10.0S",
  "3.10.1S",
  "3.10.2S",
  "3.10.0aS",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.7S",
  "3.10.1xbS",
  "3.11.1S",
  "3.11.2S",
  "3.11.0S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0S",
  "3.13.1S",
  "3.13.2S",
  "3.13.3S",
  "3.13.2aS",
  "3.13.0aS",
  "3.13.5aS",
  "3.13.7aS",
  "3.6.0E",
  "3.6.1E",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.5bE",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.15.0S",
  "3.15.1S",
  "3.15.1cS",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.3aS",
  "3.16.4aS",
  "3.16.4dS",
  "3.17.1aS",
  "3.2.0JA",
  "16.5.2",
  "3.18.0aS",
  "3.18.2S",
  "3.18.3S",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2aSP"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCut77619"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
