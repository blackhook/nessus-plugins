#TRUSTED 1cdc9bc8c8a86aab3d35f301c1a8b23066cc48102bf3efd30c144015b251af87290cd3232653e7876b54dba92a1180bc56280723b6f2bbc5658e5cc816a94840c09f8ca2eef5bf67b681df16deee4a464a0e594894cfef91c7d28b6f10d3b64457930b958568661016f7dd27f930158fc12fb10dec1c06f1dcc8112a2e55f562b44f72800064bef61b12b70c895d4656eee84d32e415d08aa75fb7ac4a43b93a4f1f7fca110df730350aa73b53abc8c2c644be4f1646ded10253622542b5cd1f7a0349e597b9b302c5d67b9c3200b7d5017b946e3651df1ac8d2e9837b105e4264f822271de4c7bb159ec3fddf79bb7b1362e16424412d6aecb0b7fcb9f749a1bd522bbc6432978631f971d8fff2eba829b34349b45cdab8bb88ca208e609301c0ba62d57760b42d04e26bc77f67ff250d423b4b2bf749a0b4c54e2aa8285b02d69ff38b5f896edb3299d0f11719ac744d13bf2a8cbbff4596664b36c7069a36142c9a3a9bf8fbce8722b3444fdc741736884a6d7f83dc1bddac4dd69a912807bb66ce75f7b448789a56fc42aae5c4542b4e8619c18ddd185b8de4982e50b21d19d167d3b0f7e0d9abf6bdd9999c8523102d9a09a2c56e71a7337a8cf83539bf916cc886d0fe1b9a0c2395dcf369ca0b2b72b1eb2b19440ab1340ae868c31bb23489164576c35a441ebef001f8681400cac61d85dc814d907f20d386d58956c2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117952);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0466");
  script_bugtraq_id(105403);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82806");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ospfv3-dos");

  script_name(english:"Cisco IOS XE Software OSPFv3 DoS Vulnerability (cisco-sa-20180926-ospfv3-dos)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ospfv3-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c10abe5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82806");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuy82806.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
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
  "3.13.6aS",
  "3.13.6bS",
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
  "3.17.0S",
  "3.17.1S",
  "3.17.2S ",
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
  "16.3.1",
  "16.3.2",
  "16.3.1a",
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
  "3.18.3aSP",
  "3.18.3bSP",
  "3.9.0E",
  "16.9.1b",
  "16.9.1h"
  );

workarounds = make_list(CISCO_WORKAROUNDS['ospfv3']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuy82806",
  'cmds'     , make_list("show ospfv3")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
