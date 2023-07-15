#TRUSTED 3eec128e8ea58f0ddb672aa3d2c195fb541d27d7894e5d1943805c0d3cd4e4d7b27feba67c123d7e2d11f3b577545129168fd3e20d2ea6ec7e374928573409d52bd5586a8fba12e0411d94bf7a6f08c4f4c6097f179920e06284a28001102aa49d61263b3f6e8e54114bf19ce4f9022eff53b09a60648bc3591ea4bf6e88bc91d03aeb49e1be4b257b61adfd8441843df06095b0a9c54144d6cc72b5c8bc8d4a82af731405c6efd54f8407943323e8a67949918bd21daff6c80334357fb264283f4664664d8e3461232b6a7c2842a74e953423f471614134b1c7f9977005cefc1d94a5bd4eb5ae6b826ec2ffe9ae7d585c16997ba64a9b6e020db520f76967e4009cea8e8bdc07d4f77e2312c909959008f4a9e716607093d54b6362be18b9ab4ffb9c9dec745afdc4fd3b33a965d941b730c351eac5034f7188bab5bd66519f4c67745a561a585baf0aa0a6cf12a5e30c6e8e82ace2a556af595ac4d2dfc4d65d4595520c6cfc9351fefad51870cac65e479e7355905fd3b0437080f1f26c2383b2d580352344ec3e9110bdc163ae015a6015ba4bac44773877c8084b1a2df0b1fd9b52d19d16b34d92d6fbbdb6fa4ea263f0ca14cd9219db8e33f948cf87476917639a61055a13fc6de5cc59ae9f0ac1144efe9975ee1f2088b981fe0791a415d511294b6139a1c4eff2f5a45410c87ea93b0dcfa2933cbcf14b31b2cfa873
#TRUST-RSA-SHA256 0e1f8836df3ae173e0191c8cea7659c0265594ea28f34f116b7c38f55f686ef09fb374b55a2cbc6ab57f3a25374c860c65fb11429b52951d9b161b0309f17a759c795e529c3c77ad16f3409a2989c0fbc1d0a2d82be9afadeb019933a71a970d83dffc610d5b7e331c43d3d85e94f8c2bcbfe4e14aa73984e348593ca383f7c6e88f5fe88218fcc846d79b6a312b1005549fd7781bbe4d2b61dbd2edb9e86fa7dc5efba9a9727aaffd619834e1fbd06939a646a773de60eab3d7116988c436772309c9590a00299c51c55da990592869638fe42df7aa905e87228073f6e5d06d00f3b5513ad59a8b779c1379886843541eb4f3eaf32738534eadc3c7bd6fd055e9a6ec7c58eef3d1838c8094f3319018b1c6c4e8bfa4e38d501cf43e6c59c57293e1e190b921b3e4673663dca9abd6773e0085a1c0a02c5b97465a7354241a26f6e5d4c45bb062e61c1b4029e6d43455a1b2c0abfd91f05acdddc6be48e13019457d73c7fba02a04a0bd8de06fdfcc3cb7b3cb26dd4c847a6a75c65d440304f82be14fe0cd2e61bc13cf99bdb9a4daaca5fdd759bd23db47d5a71c78c7d4c81df64a2e3ca5adb2d8a7b3f30d7423644245cf9fd7932520014ea2dc375c2702c93af99cb4bdfb730ea4ffe64ecea226486970ce0d94dd5f81ca992579ea38c3563df12896025255366aba2e3386b6901e90a97b8b6e525738807e79abbccbc8b5
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103694);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12237");
  script_bugtraq_id(101037);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc41277");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ike");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e9f54a3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc41277");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc41277.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12237");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.3a",
  "16.1.4",
  "16.2.1",
  "16.2.2",
  "16.2.2a",
  "16.2.3",
  "16.3.1",
  "16.3.1a",
  "16.3.2",
  "16.3.3",
  "16.3.4",
  "16.4.1",
  "16.4.2",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.1c",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.10.2tS",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.7S",
  "3.10.8S",
  "3.10.8aS",
  "3.10.9S",
  "3.11.0S",
  "3.11.1S",
  "3.11.2S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.0aS",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0S",
  "3.13.0aS",
  "3.13.1S",
  "3.13.2S",
  "3.13.2aS",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.5aS",
  "3.13.6S",
  "3.13.6aS",
  "3.13.7S",
  "3.13.7aS",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.1cS",
  "3.15.2S",
  "3.15.3S",
  "3.15.4S",
  "3.16.0S",
  "3.16.0cS",
  "3.16.1S",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.3S",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4dS",
  "3.16.5S",
  "3.17.0S",
  "3.17.1S",
  "3.17.1aS",
  "3.17.3S",
  "3.18.0S",
  "3.18.0SP",
  "3.18.0aS",
  "3.18.1S",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.2aSP",
  "3.18.3S",
  "3.18.3vS",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.0S",
  "3.6.1E",
  "3.6.1S",
  "3.6.2E",
  "3.6.2S",
  "3.6.2aE",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.6E",
  "3.7.0E",
  "3.7.0S",
  "3.7.0bS",
  "3.7.1E",
  "3.7.1S",
  "3.7.1aS",
  "3.7.2E",
  "3.7.2S",
  "3.7.2tS",
  "3.7.3E",
  "3.7.3S",
  "3.7.4E",
  "3.7.4S",
  "3.7.4aS",
  "3.7.5E",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.8.0E",
  "3.8.0EX",
  "3.8.0S",
  "3.8.1E",
  "3.8.1S",
  "3.8.2E",
  "3.8.2S",
  "3.8.3E",
  "3.8.4E",
  "3.9.0E",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1E",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2E",
  "3.9.2S"
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'],CISCO_WORKAROUNDS['show_ip_sock_ike']);
workaround_params = {"check_queue_limit" : 1};


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc41277",
  'cmds'     , make_list("show udp", "show ip sockets")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, router_only:TRUE);
