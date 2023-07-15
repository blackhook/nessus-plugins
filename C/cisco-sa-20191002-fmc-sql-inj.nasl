#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129850);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2019-12679",
    "CVE-2019-12680",
    "CVE-2019-12681",
    "CVE-2019-12682",
    "CVE-2019-12683",
    "CVE-2019-12684",
    "CVE-2019-12685",
    "CVE-2019-12686"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh03939");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh03949");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh03955");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77430");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77600");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77847");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn69019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-fmc-sql-inj");

  script_name(english:"Cisco Firepower Management Center Multiple SQLi (cisco-sa-20191002-fmc-sql-inj)");
  script_summary(english:"Checks version of Cisco Firepower Management Center");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is affected by multiple SQL injection
(SQLi) vulnerabilities in the web-based management interface. These vulnerabilities exist due to improper validation of
user-supplied input. A low-privileged, remote attacker can exploit this to inject or manipulate SQL queries in the
back-end database, resulting in the disclosure or manipulation of arbitrary data.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-fmc-sql-inj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b45afcf3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72541");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh03939");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh03949");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh03955");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77430");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77441");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77600");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77847");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn69019");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh03939, CSCvh03949, CSCvh03955, CSCvh77430,
CSCvh77441, CSCvh77600, CSCvh77847, CSCvn69019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version': '6.0.0', 'fixed_version': '6.2.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'sqli': TRUE}
);
