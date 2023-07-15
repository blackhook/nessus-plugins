#TRUSTED 03aa78766818e64a67e2046732f4ba3922b4f4ab09e2d27475e9c5fba22471cbac95ea08b8b334b03a6d190074c78ae742030eecf98027c4d086999268ab90009405ef5a35a8122659db527362495f979058238abe39f44042fd0fd1796fdc38f177e60d7ef2624d7dcf2dc73e6cf23856b5151323700982ba426b3d84d7ba4aded53c91ea1c54f6d2f07b3dd789aea4570d513824e36d2e0b5d9f03a6023bfd31b5e1dee1d0763d49088153b2a66ede46c7c4b73db5cb4d0724eab04afc562132d3934dc98dd7f0c3c3f9627db27fab627406c694df5e364d8f700d97fa79a7f42a26ea2f31853dbe54d97f7f63bc5bed3651df2240f14abd096bc1c077a8ddb0b63fa5e197168b2ed4815b1422c9f226ce89a95d736b9cb702fec434bcd7b0f7669d38785c545a0f0465b39e2a624785ec939b9c9a5937989cc73bd95f449e17eeddea3e20e045c6316cda5c3c63284180a0307c25cb8fdf0311143b9a7423c3c39b76df43301e61d84fbbdfcca499981278cd125d7452592df844ccdc5bf61d93c86ddf096e68cfd8441d1e42c9a2822ceb7299522d44d033d6045911944d304e30d89c3d5580f4eaec6ced3f4cbb02edacade19a295ea7ccd9545d46c7e68415290d1630592a7cf5eae67a39faf13423fc1decb4c4254b6c35392d95a61e1484088675904b15bef90ee0a4b12ddca9637d23c5b947b2687618b0432589be
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118821);
  script_version("1.8");
  script_cvs_date("Date: 2020/01/09");

  script_cve_id("CVE-2018-15454");
  script_bugtraq_id(105768);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm43975");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181031-asaftd-sip-dos");

  script_name(english:"Cisco ASA Denial of Service Vulnerability (cisco-sa-20181031-asaftd-sip-dos)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
a denial of service vulnerability which could allow an
unauthenticated, remote attacker to cause a reload of the affected
system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181031-asaftd-sip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80f71c25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20181031-asaftd-sip-dos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

if (
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  product_info.model !~ '^55[0-9][0-9]-X' && # 5500-X
  product_info.model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  product_info.model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  product_info.model != 'v' &&                       # ASAv
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  product_info.model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SSA
  product_info.model !~ '^93[0-9][0-9]($|[^0-9])'    # Firepower 9300 ASA
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

vuln_ranges = [
  {'min_ver' : '9.4',  'fix_ver' : '9.4.4.27'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6.4.18'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.3.16'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.32'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm43975'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

