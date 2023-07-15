#TRUSTED 892ee4c0f44cd47ec4d9c9a79e896716e4c657484eeb5dc4584675283a2af1b6b4a47ac9b615f2e5ee89c114619d0d391f085bb3d2c2935774a20b8343848130f3b32d6e5f1ae5f128798f50c392ad81b970dbe4c80dc37c5fa6915cc2e4007e9071f53b0a88d3f5b41c287068af20d3e1303158e8d2e2328f80925c5faa442700fb44a9f248cace19337c900720c9543bf91442b1b3dfcd3fa2ffe03e3756f49a3146ffe46b37137951c8b5f1a1b8c769d8a556780eebaebc70caed520a65894843ef029e61443e7553fd9084bff29603104da961e6a06c4370632e1a092536ac479184967af6fbe119a195143b20f416ad0ba1fc2eaeea5d01f3eac84803c1ac3574156422e24429a052b8d9f110dd5f71b11911044e0a384943ed2c072f2203ca3f1b7dd8a8d19856ccdc8e2e59d0d897a523c6d90ce89e244f0867255761b23afc668967a8e8bbad2695566491575417152ea8769e67243628af8bb2022b78bad7cdb613a7194eb80dce41cb60e8fc09b7836c9dfd4eaff14cdcf099f90bd06ba9f182a3a5c1d5eee2f802f66ac9b4f3f1cb701af6fdf61f99735c0df1b012c861776901e9a44e01dd32008dc6576a4afa604cf71bc77a1303a02e4aa13eca2cc0a40f1184270a01f3f36f54ec3179fd860e9dd534542a5e25da130e4c1b85fb66b43b2e7bd334c702d2f0c1df90a6f1a355cf0d2ccab019a7ec67402512
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140273);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-3546");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp01770");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-info-disclosure-vMJMMgJ");
  script_xref(name:"IAVA", value:"2020-A-0400-S");

  script_name(english:"Cisco Email Security Appliance Information Disclosure (cisco-sa-esa-info-disclosure-vMJMMgJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by an information disclosure
vulnerability in the web-based management interface, due to insufficient validation of requests sent to it. An
unauthenticated, remote attacker can exploit this, by sending specially crafted requests, to disclose potentially
sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-info-disclosure-vMJMMgJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?367dd0c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp01770");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp01770");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

# Cisco ESA software releases 13.5.1 and earlier
vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '13.5.2' }];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvp01770',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

