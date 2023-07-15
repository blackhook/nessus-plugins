#TRUSTED 461ff6d4316e827bbdbb5ad649d786a1c13daf0d8b927031545ede0b3696e8ec5ee930273381d3655e8d1f48527e57e69fd8b7134582e5d774f7c82b21874e7a4a65db03e0b3ce02ca016f46692e5c66c1289a1ad930c97f7915a5e63acb55020102d0f78fb7e9d5e29e68364bd7a573db31876ea8f257a442a3022c35233f64e5cbaf1c0f479671772d0d814ad317a39efd0f53fd31b321b4303d822386f9d0ff6b3dfe40fd154ffc538c9a3919c4cd783c2b3863749dd7d13ad35e55987c954a0bb043ff82a473dd5fc04d23a5c241846fcf8140458a346fb1b10ba3114f10aae175265210828f28dff3405948d22ca0a87b3319c3d6796408c1467be91ae966c495532d8bb8b057b8fc48cc484cb7c1f1f48fcf659c1e2f1444330acb9db0e723c99ce78571578566161c592e3c4a683f8fd8de532aec04dbe9b35b9de330ee1969dfe138bae51597c426785185665b76d675ad2eb6688c8db1c2181cfa56d0baca46d617232634d0d66b230c20b1a7d75fec5ceb36ba2031546e300857f052b4871c7ad834f4bbf1a90336b5c8e45ea70d1d141cffa686cbae110f21261b53e37c81ad0b9052c212936fe9c626ea9774dae81c0489b385f6f3cfb1366cb106fe706aed255183845d3f0f2250f89f2ab932df2da36df7ced37de7c5dd2fb68aba260d58fdeab6840933778ea27e3d2911d27c26c38917d6be1581325ea65d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147147);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-1425");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw39308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-info-disclo-VOu2GHbZ");
  script_xref(name:"IAVA", value:"2021-A-0116-S");

  script_name(english:"Cisco Content Security Management Appliance Information Disclosure (cisco-sa-esa-sma-info-disclo-VOu2GHbZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in the web-based management interface of Cisco AsyncOS Software for
Cisco Content Security Management Appliance (SMA) due to confidential information being included in HTTP requests that are
exchanged between the user and the device. An authenticated, remote attacker can exploit this, by looking at the
raw HTTP requests that are sent to the interface, to disclose some of the passwords that are configured throughout
the interface.

Note that Nessus has not tested for this issue or the host configuration but has instead relied only on the
application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-info-disclo-VOu2GHbZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?365a1f2d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw39308");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw39308");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(201);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Content Security Management Appliance (SMA)");

# necisary for combined checks
if (!empty_or_null(product_info['port'])) port = product_info['port'];
else port = 0;

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '13.8.0'}
];

reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
