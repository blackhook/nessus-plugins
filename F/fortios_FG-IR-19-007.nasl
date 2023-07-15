#TRUSTED 68f1128ce688c0bbcf3a9a9d0977eeec73d18badbcecb2ce6303a3e0f5008b620624180cd75b69745ff1ab0801cc1b766a61d33f141b66de9232afe047010d8a027a24ac874ffda17d6a994abe004b759b409fd94ce1ad207d7482fd0a0b534565a10edc4dca01ea6e3950c0b2671a536eec528d0dec469e39c0b1d8315ab76bc218bd8a487e69747251d4eb39b0f34a40fb6ce66b3914892d741c4b9bf160f8d636003567095bf02921cce2cace472c8da7cd761ee57828714d1dd6a131dc468111527b3a5bfb87d3bfc93f58cea0ad304cf9f4739aa79b6d28541b28bad8b09d2823517f455850590ff60f92178f9628455d0d81974090a169050bda28bfcf8a62ab1d4922fa5b47634ca214f798dbef2978a572547bdeb396057f3832c590736df22c26247e10f1c14b8a1558c5e2a7005a1066515cdab203503b36de0cbc0ff8713288c81d41d96a036122b134711bb09c131750d81e82ef13bd47e360f5be5f8b4bd6eb4edea840675ea8fc66ea03f3a325799adceb8074d0f28ce52c6beb200fab7ce528e7c146760223b94ab399e5b92e51f789826b0fb9eb27e654b8e2fdb6731e06d9ec2b859c008a1ec095472d729fe230b7307a1627c699201d863f28fbe148c482f5f1b10e824082a1547803c96f81294095175ad1aa4810a149030124f35b2058d58b457108a26ee5bb997e8f47de0d1ce27a54f73a4c7af3a8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132317);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-6693");

  script_name(english:"Fortinet FortiOS < 5.6.10 / 6.0 < 6.0.7 / 6.2.x < 6.2.1 Vulnerable Encryption (FG-IR-19-007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of FortiOS that has not yet enabled private data encryption.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS that has not yet enabled private-data-encryption. A 
authorized remote user with access or knowledge of the standard encryption key could gain access and decrypt 
the FortiOS backup files and all non-administor passwords and private keys.' (CVE-2019-6693)");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-007");
  script_set_attribute(attribute:"solution", value:
"Ensure that Fortinet FortiOS has been updated to 5.6.10, 6.0.7, 6.2.1, or later.
Additionally the user will need to set the private-data-encryption attribute 
based on instructions contained in FG-IR-19-007 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");
  script_exclude_keys("Host/windows_local_checks");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.11' },
  {'min_version': '6.0', 'fixed_version': '6.0.7' }
];

report +=
  '\n  FortiOS is currently running a vulnerable configuration,'
  +'\n  Based on private-data-encryption is currently not enabled.'
  +'\n  Please ensure private-data-encryption is enabled.\n';

vuln_settings = [{config_command:'full-configuration', config_value:'private-data-encryption enable'}];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, vuln_settings:vuln_settings, report:report, not_equal:TRUE);