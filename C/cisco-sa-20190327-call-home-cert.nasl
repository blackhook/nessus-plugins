#TRUSTED 48f85ac5bcdf21a074367de28a3b24bcac8da90039317cac258f095fb22a7955c30a11170c7f312697d98ced584243fe3c76aa78a79d810a6870d35924cbf03e5813c11263ee86c688d0d29114b56904723abdaac74a91283f23c857c50c7454280aa0f668ee5a95c6ef79ad19452c5f5af5063181a89f924f774404de8b5435c50ee6a5b3e6b8459cf1fe87ec29dab0688a6037f35bdb12e819eef6266989eec677a61f74bbeceb22a3fac38d25743b175b3d24271743509517e68b3e76d136904f3829e46c1df584dd7a77970f0e0ce63ab5c8acd04d9ef9607536fbb71ae955ff4c9351c40e85242da5964b16985ea7de9a0982ed171d3286b91bdd7c7d55712adb15f99860cfe15403ac400a1683bc657dd5e399239b6b58a7cfc1752283610e31998bfc8252c77a88ac799e9e7f4c517748105f6771ae24bda7b41690d9e72d83f617597098b8aa80e6f8c5ef7563231a8d98b3f9faea4f68472d27a9a3659b3c27b6fa1ae4b2e7483142d9baeab9b8a54c8dab7cc459adc026d14b41e7abcaedbc402f119125765bb500cdaa09a0274cbe2dd3450d0d32b61deb5ef3d9f00eaa8907240036c489ddd0ea796f4980d3abccb0a977b88c675ad582cfbe8850c0fda2a9b965e48d9c06f980238d8ce96f928591f9097df9066e59c6e251302745155a03a8242bd73518bb46e5eb84c13b562046fc2fe1c64d0d9e8d73adad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123790);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2019-1757");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg83741");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-call-home-cert");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS and IOS XE Software Smart Call Home Certificate Validation Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Cisco Smart Call Home feature of
    Cisco IOS and IOS XE Software could allow an
    unauthenticated, remote attacker to gain unauthorized
    read access to sensitive data using an
    invalid certificate.The vulnerability is due to
    insufficient certificate validation by the affected
    software. An attacker could exploit this vulnerability
    by supplying a crafted certificate to an affected device.
    A successful exploit could allow the attacker to conduct
    man-in-the-middle attacks to decrypt confidential
    information on user connections to the affected software.
    (CVE-2019-1757)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-call-home-cert
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d1ccbd4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg83741");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg83741");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(295);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.9.2bE",
  "3.9.2E",
  "3.9.1E",
  "3.9.0E",
  "3.8.6E",
  "3.8.5aE",
  "3.8.5E",
  "3.8.4E",
  "3.8.3E",
  "3.8.2E",
  "3.7.5E",
  "3.7.4E",
  "3.6.8E",
  "3.6.7bE",
  "3.6.7aE",
  "3.6.7E",
  "3.6.6E",
  "3.6.5bE",
  "3.6.5aE",
  "3.6.5E",
  "3.6.4E",
  "3.18.4SP",
  "3.18.4S",
  "3.18.3bSP",
  "3.18.3aSP",
  "3.18.3SP",
  "3.18.3S",
  "3.18.2aSP",
  "3.18.2SP",
  "3.18.2S",
  "3.18.1iSP",
  "3.18.1hSP",
  "3.18.1gSP",
  "3.18.1cSP",
  "3.18.1bSP",
  "3.18.1aSP",
  "3.18.1SP",
  "3.18.1S",
  "3.18.0aS",
  "3.18.0SP",
  "3.18.0S",
  "3.17.4S",
  "3.17.3S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.1S",
  "3.17.0S",
  "3.16.7bS",
  "3.16.7aS",
  "3.16.7S",
  "3.16.6bS",
  "3.16.6S",
  "3.16.5bS",
  "3.16.5aS",
  "3.16.5S",
  "3.16.4gS",
  "3.16.4eS",
  "3.16.4dS",
  "3.16.4cS",
  "3.16.4bS",
  "3.16.4aS",
  "3.16.4S",
  "3.16.3aS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.2aS",
  "3.16.2S",
  "3.16.1aS",
  "3.16.1S",
  "3.10.1sE",
  "3.10.1aE",
  "3.10.1E",
  "3.10.0cE",
  "3.10.0E",
  "16.9.1s",
  "16.9.1c",
  "16.9.1b",
  "16.8.2",
  "16.8.1s",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.2",
  "16.7.1b",
  "16.7.1a",
  "16.7.1",
  "16.6.3",
  "16.6.2",
  "16.6.1",
  "16.5.3",
  "16.5.2",
  "16.5.1b",
  "16.5.1a",
  "16.5.1",
  "16.4.3",
  "16.4.2",
  "16.4.1",
  "16.3.6",
  "16.3.5b",
  "16.3.5",
  "16.3.4",
  "16.3.3",
  "16.3.2",
  "16.3.1a",
  "16.3.1",
  "16.2.2",
  "16.2.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['section_call-home']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvg83741"),
  'cmds'     , make_list("show running-config | section call-home")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
