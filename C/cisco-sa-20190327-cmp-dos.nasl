#TRUSTED 5bf3ac9219c2213bbd9d777133f341cb8a1310c3152f999589b8d8de024649be1291eb60029eece2340a429fe4b6b4907529bfefa105471ad0f6617c11a59dcae878a4e1794c0e4b7286e824d979d10786b88115c56727e6f95b885569b5072f99581ea5ec72af5e8c2c25cfc6166d1c516514a31a5c73a58cf0ab6f6d42c49059655ae16443113a3672da41d0e115b394420b9f3b8be6c5b9b044298d6d00bde7ab11189f26feea43704fbc00b24db06fb315323000ab308a10e65efba0c8a308b32be5d4fd76b9967e7365c52a081a8000778f593324a1786756aff0ee0ebce8022efe6c0587b9a0ba9a2d2057d02bb8c7a341ca22d813c9237f367547d57a434904437aa2b349d74f1a827aa44278a99ee9d388c0bc2c2c162dc2c774dc934ebb53a3104e4927204fd1612dfef05a7be219ccba1ea56fbbd68547bed9b710f297550728aea3e92603fbd672aa49ca44b1548fba68c28d01e6c5251aa4ecac9d2219fb9b4e99a56286766de87a363b49fad48467f748481daf230fd407e2b18916586c604614ef21423af3e8ef1534228e4cc3522c2d2d1e97fb922212619a017bde482ecb3e50ae9329f9a4bfc67594264f723620d5a881c4fb351ebb19f90031f7ab3565f868072365821424e58e7583cb849354b95586c95fcf9a7d62381b56843ae35563a13a0d1eac862750891e7283156621f2c27ca9f25ad3c71718
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124277);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1746");
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj25068");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj25124");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-cmp-dos");

  script_name(english:"Cisco IOS and IOS XE Software Cluster Management Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by A vulnerability in the Cluster Management
Protocol (CMP) processing code in Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, adjacent
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient
input validation when processing CMP management packets. An attacker could exploit this vulnerability by sending
malicious CMP management packets to an affected device. A successful exploit could cause the switch to crash, resulting
in a DoS condition. The switch will reload automatically.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-cmp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69f78412");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj25124");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj25124");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1746");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.9.2bE",
  "3.9.2E",
  "3.9.1E",
  "3.9.0E",
  "3.8.7E",
  "3.8.6E",
  "3.8.5aE",
  "3.8.5E",
  "3.8.4E",
  "3.8.3E",
  "3.8.2E",
  "3.8.1E",
  "3.8.0E",
  "3.7.5E",
  "3.7.4E",
  "3.7.3E",
  "3.7.2E",
  "3.7.1E",
  "3.7.0E",
  "3.6.9E",
  "3.6.8E",
  "3.6.7bE",
  "3.6.7aE",
  "3.6.7E",
  "3.6.6E",
  "3.6.5bE",
  "3.6.5aE",
  "3.6.5E",
  "3.6.4E",
  "3.6.3E",
  "3.6.2aE",
  "3.6.2E",
  "3.6.1E",
  "3.6.10E",
  "3.6.0bE",
  "3.6.0aE",
  "3.6.0E",
  "3.5.8SQ",
  "3.5.7SQ",
  "3.5.6SQ",
  "3.5.5SQ",
  "3.5.4SQ",
  "3.5.3SQ",
  "3.5.3E",
  "3.5.2SQ",
  "3.5.2E",
  "3.5.1SQ",
  "3.5.1E",
  "3.5.0SQ",
  "3.5.0E",
  "3.4.8SG",
  "3.4.7SG",
  "3.4.6SG",
  "3.4.5SG",
  "3.4.4SG",
  "3.4.3SG",
  "3.4.2SG",
  "3.4.1SQ",
  "3.4.1SG",
  "3.4.0SQ",
  "3.4.0SG",
  "3.3.2XO",
  "3.3.2SG",
  "3.3.1XO",
  "3.3.1SQ",
  "3.3.1SG",
  "3.3.0XO",
  "3.3.0SQ",
  "3.3.0SG",
  "3.2.9SG",
  "3.2.8SG",
  "3.2.7SG",
  "3.2.6SG",
  "3.2.5SG",
  "3.2.4SG",
  "3.2.3SG",
  "3.2.2SG",
  "3.2.1SG",
  "3.2.11SG",
  "3.2.10SG",
  "3.2.0SG",
  "3.16.1S",
  "3.16.10S",
  "3.16.0bS",
  "3.12.0aS",
  "3.10.4S",
  "3.10.1sE",
  "3.10.1aE",
  "3.10.1E",
  "3.10.0cE",
  "3.10.0E",
  "16.9.2h",
  "16.12.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['cluster']);
workaround_params = {'is_configured' : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , "CSCvj25068, CSCvj25124"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
