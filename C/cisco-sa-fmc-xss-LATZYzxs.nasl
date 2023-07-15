#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168326);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-20831",
    "CVE-2022-20832",
    "CVE-2022-20833",
    "CVE-2022-20834",
    "CVE-2022-20835",
    "CVE-2022-20836",
    "CVE-2022-20838",
    "CVE-2022-20839",
    "CVE-2022-20840",
    "CVE-2022-20843",
    "CVE-2022-20872",
    "CVE-2022-20905",
    "CVE-2022-20932",
    "CVE-2022-20935",
    "CVE-2022-20936"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa64739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa93499");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb01976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb01983");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb01990");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb01995");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb02006");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb02018");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb02020");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb02026");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb61901");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb61908");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb61919");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb88587");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc10037");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-xss-LATZYzxs");

  script_name(english:"Cisco Firepower Management Center Software XSS Vulnerabilities (cisco-sa-fmc-xss-LATZYzxs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Management Center installed on the remote host is prior to tested version. It is,
therefore, affected by multiple vulnerabilities in the web-based management interface of Cisco Firepower Management 
Center (FMC) Software could allow an authenticated, remote attacker to conduct a stored cross-site scripting (XSS)
attack against a user of the interface of an affected device. These vulnerabilities are due to insufficient validation 
of user-supplied input by the web-based management interface. An attacker could exploit these vulnerabilities by
inserting crafted input into various data fields in an affected interface. A successful exploit could allow the attacker
to execute arbitrary script code in the context of the interface, or access sensitive, browser-based information. In 
some cases, it is also possible to cause a temporary availability impact to portions of the FMC Dashboard.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-xss-LATZYzxs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9610dad2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa64739");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa93499");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb01976");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb01983");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb01990");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb01995");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb02006");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb02018");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb02020");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb02026");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb61901");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb61908");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb61919");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb88587");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc10037");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa64739, CSCwa93499, CSCwb01976, CSCwb01983,
CSCwb01990, CSCwb01995, CSCwb02006, CSCwb02018, CSCwb02020, CSCwb02026, CSCwb61901, CSCwb61908, CSCwb61919, CSCwb88587,
CSCwc10037");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  {'equal':'6.1.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.6', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.1.0.7', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.0.6', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.2.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.2.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.2.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.2.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.2.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.6', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.7', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.8', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.9', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.10', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.11', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.12', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.13', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.14', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.15', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.16', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.17', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.2.3.18', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.3.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.3.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.3.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.3.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.3.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.3.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.6', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.7', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.8', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.9', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.10', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.11', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.12', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.13', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.14', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.15', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.4.0.16', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.5.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.5.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.5.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.5.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.5.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.5.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.5', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.5.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.5.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.6.7', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.7.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.7.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.7.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'6.7.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.1.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.2.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.1.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.1.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.1.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.2.0', 'fixed_display': 'See vendor advisory'},
  {'equal':'7.2.1', 'fixed_display': 'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
