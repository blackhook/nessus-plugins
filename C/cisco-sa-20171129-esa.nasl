#TRUSTED a9de4294d6215972b5795de603a0cbc0b2e7ef9536af744d311aeb595441d0d81df0f4413f9af17543f6be1dfa4ec6c8536be69230ef19ab4cd70b4c01d94adac90fc72a242362040adddcf723155352a63b5438035d81f29309bada5bedd6c9c35f2cb6261ca8f4c2c860cb36e88dde0e441a35a1c48ac3222453d632caaacc418d7f824e73c2e64dfcf92a5835fea1cb925287b8d6705dae01ce77b1f3a45ad6ce75eb94dd5fc10afa8a0c83962e9b89cd76545402d101e353ff347c39275c1df073a7ba51aef9c658bfd0ac7ba06781c08e270f3fd04fa71bccee6f5bae610148c0f12dc8b170cb327d551529256977f6efa401e2157fd11b61df947ee0c8c57c7678bd504df45a99014cbb8ec9b981ecac24b0a96d0f075b8ffe1a89fa268e1b2bdb582a176bc918603a006f43ec7ad843bfd197ec8644e05ab9b4738e6b628cbd46611d578c540a30df9c76ee481bdfbaaf93fe9714a4a5607fd41c24476869fc04ebf038048db6f966f144fe02bbf69009197b07b80d352170783b501347abd95c33262bde45215e2be68a8e5ff030cfbeffaa8bed57e2a6dc1c6381ce579b27ea4761a25ff7a5c18fb4b49e0c8d62dcff04dddfc7d796b526b7cdca5d37e83cf5697e5320309a5124b36dfa33094ec0d304d4c79c7fe0a7fc42dd72358168c285d02ebbb2ecdad67adc5393e78a0068ec683d9e72f2771691b76ef300
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105257);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2017-12353");
  script_bugtraq_id(102002);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf44666");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171129-esa");

  script_name(english:"Cisco Email Security Appliance Filter Bypass Vulnerability");
  script_summary(english:"Checks the Cisco Email Security Appliance (ESA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security
Appliance (ESA) is affected by one or more vulnerabilities. Please
see the included Cisco BIDs and the Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171129-esa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33a0a792");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf44666");

  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf44666.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12353");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Email Security Appliance (ESA)");

version_list = make_list(
  "9.7.0.125",
  "9.7.1.071",
  "9.7.2.047",
  "10.0.0.203",
  "11.0.0.264"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , "CSCvf44666"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
