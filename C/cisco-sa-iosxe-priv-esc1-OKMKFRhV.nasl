#TRUSTED 0149c69b7260e76f420b1bd1eab5202e571f27986b231cb96dc9117761f29f946066571ce00803892d38d0fd2b176c96eb1f8e235edfa197d2f5dce35aca4508ebad1ca3aaa9a935d669462f0cb9980673e31390f65b9fe1159b3ab5fd29468fda2e2aef084a9fd01f9b88a8bdb0fe9c72aaee2fb0dd5758adcd8ad5e58da00218ab1d76ec6d86c3b76d0ddf186c382a3d8de78d120f9ddb83caac3da2a9f44606bca9caa2b01bdf203ea71d1859cbbaf11a9a11b1d37c0142b33bbaf9c10fb1d5b89a71b7ec609cb38c41dbcddabcd4dc06e067229d302772a9afb44e4bdd8dbdea8cc772818ef6b1cf91e0f136204e4f078fba41339c053e7ece66b6d2b9126628b6f6d6ddda8225eab936a8b2d0bf37571990d423fabf9fb05c547b419489c522b8211998caba118d013f7ee03327ca0c836edf88b124f89fbc5ce94c69172fcc9ac8f1312a175c7b22184f21041cca0923f9a6b46cd3806e1a37c692c96511c5c0c3d8e30b99e40d8ec7a983a174e92065f7424e5a3b27f544e392c48bcb31a046a491f9a7e13d59b3f41c09e0c7a145bfaec15dba503d9258db6737d7ba2c435b8aaa813021df59e76362903e4704cc8d21a975d3c2d501224cd5994309007de655cfeb792bdc5afc5647989943c2010c97035b219ceb103bffa29963652104c7c8a9255802282e341a747d8c610637286674d748e871dcb3b6e4ca06c6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151375);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-3215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq20692");
  script_xref(name:"CISCO-SA", value:"cisco-sa-priv-esc1-OKMKFRhV");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Vulnerability (cisco-sa-priv-esc1-OKMKFRhV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the Virtual Services Container of Cisco IOS XE Software could allow an authenticated, local attacker to gain root-level
privileges on an affected device. The vulnerability is due to insufficient validation of a user-supplied open virtual
appliance (OVA). An attacker could exploit this vulnerability by installing a malicious OVA on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-priv-esc1-OKMKFRhV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35677f5f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq20692");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq20692");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list = make_list(
    "3.8.0S",
    "3.8.1S",
    "3.8.2S",
    "3.9.1S",
    "3.9.0S",
    "3.9.2S",
    "3.9.1aS",
    "3.9.0aS",
    "3.10.0S",
    "3.10.1S",
    "3.10.2S",
    "3.10.3S",
    "3.10.4S",
    "3.10.5S",
    "3.10.6S",
    "3.10.2aS",
    "3.10.2tS",
    "3.10.7S",
    "3.10.8S",
    "3.10.8aS",
    "3.10.9S",
    "3.10.10S",
    "3.11.1S",
    "3.11.2S",
    "3.11.0S",
    "3.11.3S",
    "3.11.4S",
    "3.12.0S",
    "3.12.1S",
    "3.12.2S",
    "3.12.3S",
    "3.12.0aS",
    "3.12.4S",
    "3.13.0S",
    "3.13.1S",
    "3.13.2S",
    "3.13.3S",
    "3.13.4S",
    "3.13.5S",
    "3.13.2aS",
    "3.13.0aS",
    "3.13.5aS",
    "3.13.6S",
    "3.13.7S",
    "3.13.6aS",
    "3.13.6bS",
    "3.13.7aS",
    "3.13.8S",
    "3.13.9S",
    "3.13.10S",
    "3.14.0S",
    "3.14.1S",
    "3.14.2S",
    "3.14.3S",
    "3.14.4S",
    "3.15.0S",
    "3.15.1S",
    "3.15.2S",
    "3.15.1cS",
    "3.15.3S",
    "3.15.4S",
    "3.7.0E",
    "3.7.1E",
    "3.7.2E",
    "3.7.3E",
    "3.7.4E",
    "3.7.5E",
    "3.16.0S",
    "3.16.1S",
    "3.16.0aS",
    "3.16.1aS",
    "3.16.2S",
    "3.16.2aS",
    "3.16.0bS",
    "3.16.0cS",
    "3.16.3S",
    "3.16.2bS",
    "3.16.3aS",
    "3.16.4S",
    "3.16.4aS",
    "3.16.4bS",
    "3.16.4gS",
    "3.16.5S",
    "3.16.4cS",
    "3.16.4dS",
    "3.16.4eS",
    "3.16.6S",
    "3.16.5aS",
    "3.16.5bS",
    "3.16.7S",
    "3.16.6bS",
    "3.16.7aS",
    "3.16.7bS",
    "3.16.8S",
    "3.16.9S",
    "3.17.0S",
    "3.17.1S",
    "3.17.2S",
    "3.17.1aS",
    "3.17.3S",
    "3.17.4S",
    "16.1.1",
    "16.1.2",
    "16.1.3",
    "16.2.1",
    "16.2.2",
    "3.8.0E",
    "3.8.1E",
    "3.8.2E",
    "3.8.3E",
    "3.8.4E",
    "3.8.5E",
    "3.8.5aE",
    "3.8.6E",
    "3.8.7E",
    "3.8.8E",
    "16.3.1",
    "16.3.2",
    "16.3.3",
    "16.3.1a",
    "16.3.4",
    "16.3.5",
    "16.3.5b",
    "16.3.6",
    "16.3.7",
    "16.3.8",
    "16.3.9",
    "16.4.1",
    "16.4.2",
    "16.4.3",
    "16.5.1",
    "16.5.1a",
    "16.5.1b",
    "16.5.2",
    "16.5.3",
    "3.18.0aS",
    "3.18.0S",
    "3.18.1S",
    "3.18.2S",
    "3.18.3S",
    "3.18.4S",
    "3.18.0SP",
    "3.18.1SP",
    "3.18.1aSP",
    "3.18.1gSP",
    "3.18.1bSP",
    "3.18.1cSP",
    "3.18.2SP",
    "3.18.1hSP",
    "3.18.2aSP",
    "3.18.1iSP",
    "3.18.3SP",
    "3.18.4SP",
    "3.18.3aSP",
    "3.18.3bSP",
    "3.18.5SP",
    "3.18.6SP",
    "3.9.0E",
    "3.9.1E",
    "3.9.2E",
    "3.9.2bE",
    "16.6.1",
    "16.6.2",
    "16.6.3",
    "16.6.4",
    "16.6.5",
    "16.6.4s",
    "16.6.4a",
    "16.6.5a",
    "16.6.6",
    "16.6.5b",
    "16.7.1",
    "16.7.1a",
    "16.7.1b",
    "16.7.2",
    "16.7.3",
    "16.7.4",
    "16.8.1",
    "16.8.1a",
    "16.8.1b",
    "16.8.1s",
    "16.8.1c",
    "16.8.1d",
    "16.8.2",
    "16.8.1e",
    "16.8.3",
    "16.9.1",
    "16.9.2",
    "16.9.1a",
    "16.9.1b",
    "16.9.1s",
    "16.9.1c",
    "16.9.1d",
    "16.9.3",
    "16.9.2a",
    "16.9.2s",
    "16.9.3h",
    "16.9.3s",
    "16.9.3a",
    "16.10.1",
    "16.10.1a",
    "16.10.1b",
    "16.10.1s",
    "16.10.1c",
    "16.10.1e",
    "16.10.1d",
    "16.10.2",
    "16.10.1f",
    "16.10.1g",
    "3.10.0E",
    "3.10.1E",
    "3.10.0cE",
    "3.10.2E",
    "3.10.1aE",
    "3.10.1sE",
    "3.10.3E",
    "16.11.1",
    "16.11.1a",
    "16.11.1b",
    "16.11.1s",
    "16.11.1c",
    "16.12.1y",
    "3.11.0E"
);

var reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq20692',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
