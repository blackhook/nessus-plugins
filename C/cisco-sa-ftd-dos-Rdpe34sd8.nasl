#TRUSTED 25290a18613c60bd279c3ca7ace58f0da0317eada1b2e49ab98b7181bf301735cd8ddd084129b8648c2fc90aea8871f26200063a772651304d4106ddef09f36776b79f97d0e09be13eeab2f6568e75f2b2553f56a48b6ba461ca69e12e7c7e06d5a4469a3e3ccc8f835bf1cc95240bbb8450697bb9571674f51dccb7da9d75b5d0cd2f9f7f0ceb1320a1f23587194ef1c3cd8b4f653f4b3abf449f1fa0b9d9526cfb01be25ff0b3d67878e9d70602f1fc1a8f5386d96537df4ba681f8ce31540d11a9c51e92535e36a23311402058b8193b3c2dbbf409b2d13b7f9c335c921a42d0cd7f2da3da1307ef39afd67b54bea2d63df86f8caa9c9c6da5e499aa47a36c60598aac97d086c717514f3a9613af4dfa0b177ff6cadbb36f5e1a7ae215bdb99365371de5643e349e90534fc059b82b670296b1c666fa3691b4cc7459399851ae2c615cfaf2313e3a15e38cba778c9a05e637caaeab00e8330b1479ff04e366ad2df8be45899315fb5c5b33f73bf23cbf9bb0c8150524881b6ebafc55fc53a62ef4114327b10db93b1425b51b0e6ea82b76dc34de5c6c20d41bae7a3591531b1ef0eb97e87db77bf21850f68fec1728f69e79a17c54bf5900775e1f9e9742dcc400ab9f684d99c7f26b0eaad00f410b9bcfd16eae63b36f67453132b68990852c3746f020881bfee13bb0ed3ac40fe17d89ca203e7c881f638764694a4ed12
#TRUST-RSA-SHA256 1c3383b6b538d4e3dcf3a095517b9040e2c4ff0fd25e4dcbfa281da77acfa51c67dbafcd07308da9e248ae7bd1d0fc5d7f8de08f1c29760406f18dc6c30a8d0c6a5809581f5727557835f48911188b9ec0cdbf9fbabceb19905651ea2f5b51b05dc50b87ae2a2d77f7d0309e54810a9ef263195a7a61d7872073208595a3056a6651f3bf168476d23a01ee7f00949ec329b65264ed03a2fdbff9274628823dfecfdd9b29e7964a84c1814c598626834e2efe56190f616b37163ee4afad3b5d6df64db403fd72e43dd3d33630430eae2528973250f215545f834c8d012ffa6ba9427f98a524685a02144707514f31419dda1ef3e3f189345f2aa486a97d0f15e2cd8ac993e23edb6b5e4950b4f5d9e8bb39e3f5841178e7717a705a3d70cc614d767fd88f22a64324335e7ff7bdabd82ab1d74a9aff4058b0343cc92f6a73297b01f11e95daedef76195103b60743c83a6a743409167dd7f14afb4a8c17b5258f984ddf7c16e20bd97f722c639f9658a92810a5878220acf738113c89285754bde96b1471b16fa243711ce4346468b773e52d1d8a38c7432918eedc0c8d78d4600ad40db6660d6f96cb68ef3dd55e2281a06adb7bdec1c1197d5deaed94deb91bfd96d8419ddf41a79d713a19e8197156613cedb63d09249537773fe24f591bcc63f7767364ee0061fa9ae1425270f8f651b90dfb7aa969db1eb972acdc91fd2a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137564);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3189");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo62077");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-dos-Rdpe34sd8");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense Software VPN System Logging DoS (cisco-sa-ftd-dos-Rdpe34sd8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the
VPN System Logging functionality due to the system memory not being properly freed for a VPN System Logging event
generated when a VPN session is created or deleted. An unauthenticated, remote attacker can exploit this, by repeatedly
creating or deleting a VPN tunnel connection, in order to cause unexpected system behaviors or device crashes.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-dos-Rdpe34sd8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46a52aef");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73830");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo62077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo62077");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3189");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Plugin is paranoid due to lack of GUI config check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '6.2.3.12',   'fix_ver': '6.2.3.16'}
];

# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes.
expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs a hotfix check. If we haven't successfully run expert to gather these, we should require paranoia.
if (!expert)
  extra = 'Note that Nessus was unable to check for hotfixes';
else
{
  # For 6.2.3, advisory does not specify the hotfix name "and later", so ver_compare is FALSE
  hotfixes['6.2.3'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo62077',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
