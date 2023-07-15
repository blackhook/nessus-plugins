#TRUSTED 44fda556e84cbda4391784d7947f5c4898589e64bcce4a2e5165f2e31207dbff937d1b6f0731ee8a5edf7afc2b1cdeaf215ef9d224245a142eda51da37c0984d6307e3e0a5b36ffccba260db0a522c43ec0e30ab1636e24119c3ea583e60511693891264237b873f08304da8c7537639ab1d5a9a7b6decd3356551ffc34515210a65d5125efbe1da459fb52a4a77a29bd1ec51d2b342fa1f5ac9addfb53ea2e8d47e36f2c6cebce07682eaf7aa5fedbe1841ac40f61583b30609c45f8c7a76aee8c700f822479732f95da961fa94c35ce37a5cb0c9a16685e69d96dfd0ae9f79d4ad5e68ee38cbe5237b5d7db2f67db2af0dd4b724ca988a0e85a4d49ccce5a73f08fd944dd66256aab0c5d19f2dd61b61fe48ddabe02223345698db28536c0a8af371da36cea0e69a441316ec92a81273652a822dc725f5bf33083b15b98fedb95cddd499a915c6a528aecaf37c826b958681da8cbcc7659e6494dde11d8a7f8bfee3cef3a7ca0894a9825a3c89a22bad32ea05bf8b289215a83b768013e154e90de00efcab1e8968d1ec434ef83626e97eb5b8df43cced2375dd56032d2daadc7cf3db64d9ea80bae6203dd43c98c9d8d3135a392b88caf65a654c200f3b864c7846b18bbf4d08b3de2ab5e92dfc92505223a286a7f209bda564f9e00d8ea8f1745070605d82f183b93b545af14e2b84f40407beb0af407f0ff1c4d62a19ab
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141868);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1678");
  script_xref(name:"JSA", value:"JSA11075");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Junos OS Multiple vulnerabilities (JSA11075)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by 
a memory leak within the EVPN protocol. It, Therefore, could allow for a adjacent unauthenticated 
attacker to crash the EVPN protocol with specifically crafted BGP packets.

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA11075");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11075.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['19.4'] = '19.4R2';
fixes['20.1'] = '20.1R2';
fixes['20.2'] = '20.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If protocols evpn not on, no danger, so audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration');
if (buf)
{
  override = FALSE;
  if ('protocols evpn' >!< buf) audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);