#TRUSTED 1885e904fd6df6b7f261de3fe9122fb0d59786cefcc564cc78321d7d78d9be4ad56c5c475f2eb554dbd89415677d545fd3b308bd71eba8656ff01afb8144d61c310bfcfffc0f5b6ea047b81763d35aefe1e45279b43e0690bf4af12010eb75d67c4326bf17c7297b9388f1ca6f6885a7a5ca9bce3801eeda3eb53a52c610f2682ff9555ba8d17e810b33f92f45ffe812673c9eb63593a45eb0d4624c9b55f0533d4ca7a864a7ad2e3c5ff0bd1625c827eed9fa3304b8614f6c14250238bc0e173448efe673e732bf553d93ee37fe320c272a1627c25c627c933640e787e8cad2de1c78a911d8dd1da68980fbe6dc61641165ab178cd75629591107d3936c3dfb46851e2e9f9ea99a343ce0a7d32d05d5041201bbab4af18424e9029868806d1a7c57e75dda51e888c7be6afa93b942c29d1d5b5b7709254947af27dff126a21d3979d9fbe1f9126bb99a774504aea5dba5ba24cdc72f5c665dbbda677fdd62caf64b477ed0c2ac5c28adc54f997e537d51adc3011f18016c6a9805ec113990cbd1da7c4dbe1be207648346ca45bb3ad70af45934bd0a0ea8a2ce9ea3067705bc110af413aed5804ff324a3de1ccfd0000a543bb955a9ce4ef9e9c571bb751f420a2c2ef900560839d986a4320185cb8ebe6868f5ecc457e0674c8cc69b37f514ece751fef3d22b026502b5ee793936bf26fbf8e3ed3cb76762be852d2702592c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128546);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1955");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp27126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-esm-inject");

  script_name(english:"Cisco Email Security Appliance Header Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a security bypass
vulnerability. A flaw exists with the Sender Policy Framework (SPF) due to improper validation of SPF messages. An
unauthenticated, remote attacker can exploit this, via a specially crafted SPF packet, to bypass header filters. Please
see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-esm-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0126aed6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp27126");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp27126");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1955");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '12.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp27126'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
