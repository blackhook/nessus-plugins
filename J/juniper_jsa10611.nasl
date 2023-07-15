#TRUSTED 73366e376ed4b3e4c02523972307abc24c2387137169a0f0f7fede8a011baf94d85fdcd67d04c2db91f09dc0acf8cac70c14d0ac871d7714c760c4c16d46c02f24745d3e456565bf6c07808ac8ce6abdd045c340970c090b39acb67e934b56a6e1909c6f1c313e3b8b311d49ee857e32e1338975440edf885e22f56d725445961d24990c93efda451cd35e7c5dadb7c1f8224015a5744eb43462f40e43b739c9e6920821e490c8232b9cf89e300dad3fe52455c7a84e26c96b9dfd7c8bd9c91f7e61c5568e454b14cb63a7ab24148c9d2b8d0a11929e09ac4074d622cbbba661a45135e9e3af9bfb876a73f82e6b65a3b9a262e02223bce21dc99c5c124f068b7b93dc37cb62509d8173e6944d1e0deb463879bfb98fa543db8e074814c3342c5e6d66f7b18517c1e9750339d19c06b1a9d6328f622375fc605d8d96773003c261e1ec9d206e781eb2143e49fee267e5ea3093d2d4636596b9aa82db0f2fe2b0fe6bca4c5c3a60ef26432eb1131ef090701248c8ac7c8c2bf040d591d97c3cc4c3cb9e96d96d9e4daf0cfb253cb9463ab5bbe1737bec58fdc43e2ee5ecdaaa6c8b706d77774fff9a62bc061aa6a94bcbfabaa00c79263c9bfb5ad929deda8d6b331ca35d7c5bfa1e8009d2a9ddb8afeec94cbcd1ff8a2257c9f9f37e4ed00ce163ce28017909aba1b68e687f91eef5bdce3b3aa4156f5bbcf4b5938e132037ea
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72000);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-0618");
  script_bugtraq_id(64769);
  script_xref(name:"JSA", value:"JSA10611");

  script_name(english:"Juniper Junos SRX Series flowd Remote DoS (JSA10611)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability in the flow daemon (flowd) when handling certain valid
HTTP protocol messages. A remote attacker can exploit this to crash
the device.

Note that this issue only affects devices configured as a Unified
Access Control (UAC) enforcer in a UAC network with Captive Portal
authentication enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10611");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10611.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true"); 
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-12-12') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R16';
fixes['11.4'] = '11.4R8';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check that UAC enforcer and captive portal are enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set services unified-access-control infranet-controller",
    "^set services captive-portal"
  );

  foreach pattern (patterns)
  {
    if (!junos_check_config(buf:buf, pattern:pattern))
      audit(AUDIT_HOST_NOT,
      'affected because it is not configured as a UAC enforcer with captive portal enabled');
  }

  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
