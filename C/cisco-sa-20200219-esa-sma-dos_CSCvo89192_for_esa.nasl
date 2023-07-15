#TRUSTED 1f60f8a00946cb3ecca7ba6fe2c9d64d422c1539865351f38023cef4fe30a8626d22187956ea36a385e3ee51ec1a9db13ddfa812c0ddc2bc6eaea4e4665533460b0a23d41fbeb9dde22b2aae7e4b13cc7ba6e42d8c4e634d247bb21ed4023b8031fa549c4a5a58a4586fcba159c5e0613a1f6ffaf5d965beb87af2e33ddd1e9dd5b76a7d76d3eb702e40fecc57a602e2ee0e987b6dd494c6ab2a05b3da8e9797a2687e8181a6f51c9cbe9c2cff2282a714a0aeb20c1db8e20175d5df87349a4ac0e92bdf8474886e617b7a58c7fc392d286283fa50ce66fc6fc7bcd8ea7bf21b1cc7530554217d5d72973ff71acb54412c781fcb9956ba921b2837fa8a72bee06f16c17d6344eca2448b729cdcaa42ff62c06ebed3fa79e4dae64c4b87cb9a9ead60288b82c2e726a79c87d09ba0f8becef9c178832f555a1f627e6d8d46a839c7628e4e8a6cc875b6c4542a060a91f42a1bc8e1f8469fdbfb78821c8d5bf19e8237ffeda84614b8c17d725a7f6e6f090175e6ade850e910cb21f90ceccad20fbf76bb66eb4872aa0863c83c3b2bd4fb7e5d784eabb785e95448167b92c32a04dfeab1e0ea4aa9edea0f191e90c3e56a7ae81cfa9f3a608cb697db011da5fa61c299b28447cdbae83d22be2d2ff4a7e41f7351e4e09c0f057e3ecd53e6af6cd468d45495e1527f842ad88f8e91b4a8b7f760e62fe0b93a73bff4a3c70106ec7f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133961);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2019-1983");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo89192");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200219-esa-sma-dos");
  script_xref(name:"IAVA", value:"2020-A-0045");

  script_name(english:"Cisco Email Security Appliance Denial of Service Vulnerability (CSCvo89192)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security
Appliance (ESA) is affected by an input-validation flaw related to
the email message filtering feature that allows denial of service
attacks.

Please see the included Cisco BID and Cisco Security Advisory for more
information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200219-esa-sma-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b12c8fec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo89192");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo89192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '11.0.3.251' },
  { 'min_ver' : '12', 'fix_ver' : '12.5.0.059' }
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvo89192',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
