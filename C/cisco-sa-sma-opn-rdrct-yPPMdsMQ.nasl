#TRUSTED 74ad22c4b9c969661f090b89d98209e7d6ef0420bd6d1f3eb0825ef565771d819df40764ef8cb0d98e3191fd4e9b793b1c562ed4aea3743625732c92adf3b64be1a90f1723e59dd7553e3d4e181b8a55054cfeebc4d642a70a8c7650c7dee3923038d1c9b86307966f478164172625f3ab47e7fbd81f0d60743099ae12775407882fb8623d888dd842b325f4f069fcffae38ff5e54b194a990d29ca91053939d2e725d35f7027c33b21f85ee26d1743412a9f5f9506d3e09532e10b1b06f31eb0fa3b8d140e34be5e02122f4558b97a093266ecce3b005810f490e48b7ac8e72dc50409a4ec216bc86c6a57f84f557b90a93088b81322b876ed0fdbbb8228afdf0cc9869a3d161e4f03be8381e12ee307936f6fb6a16b088b699063c2618e46349f481629b9dc55547a9fc14d1c330cf4c6800a5a43dc6e26f0064a012ec1e6a84cde677dff36fed307e7cccb132fa0f38e58b36efe329e4adbdf1658e53c355dcea96f116b782545feb76f86d484e1c3cb9ad394d9ffb316182c5a9cf4d47169c0163839aa2dfa690d4f84b5b9283ad49566b6eac0efafb66ff38781ac4ef197c2cdfc4b76676ea32faa8d5c124a2d62b17acc84121860e128bf24cd1736b39e560771c957c12e5afb081cfe482481aa781921e719402d8b70052ac08ead07e6fb31e51bdbd2e668ee64acfbb03b0895c6bfa637ab0c3a550536571b7875ee6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136748);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3178");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq83107");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr82721");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sma-opn-rdrct-yPPMdsMQ");
  script_xref(name:"IAVA", value:"2020-A-0218-S");

  script_name(english:"Cisco Content Security Management Appliance Open Redirect Multiple Vulnerabilities (cisco-sa-sma-opn-rdrct-yPPMdsMQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Content Security Management Appliance (SMA) is affected by multiple
vulnerabilities in the web-based GUI due to improper input validation of the parameters of an HTTP request. An
unauthenticated, remote attacker can exploit these, by intercepting an HTTP request and modifying it to redirect a user
to a specific malicious URL, in order to redirect the user to a malicious web page or to obtain sensitive browser-based
information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-opn-rdrct-yPPMdsMQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6be6a784");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq83107");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr82721");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq83107, CSCvr82721");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3178");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(601);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:content_security_management_appliance_(sma)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '13.6'}
];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['display_version'],
'bug_id'   , 'CSCvq83107, CSCvr82721',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
