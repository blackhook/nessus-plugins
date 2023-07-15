#TRUSTED 50dcb7e79f36d804aad746749a6214414dc7211cd8752ba7cf06b772bb48254f8dc95022d4ed90a31fdce3d82374b9a1c27e7a62770aa84050fd0117766869a11306ad183653913b6a52c97e46a0f5f1774fa87f15687f086cb8d792cd3721344259d4827e1aa4c17848b51186a13be3d197e71bbbdb7f4ec57e26f584d18020df0eeca935ba8f550c9221f6cab7a078b0d1ec35b9569f01137d20e0bc87f670414097472f93fd43906cf9a584486650b04d2de5aef815fd3c1723ca921d702e902a6f2cb345c19aee338cdcd5db86450cd00c514d3a29de1922c6c3228714972652cbf693f86b4a4cb92ec8c7a94712f2c72b7bae317c3d2f936c018be6d2e5f8ea6317382fca1fb70783de89e548e2868052b439c0c220b872976b565f305685d33539961553feed90c3413929671426144477790cffa1ba34ca9c8a447ccf228472a4a746a29b1fa4b7ce3db77f5023c5c55c5e86ab33fc3e97b547ef7d1d337ddedd9549fd751a0912d3174d95489cc9d894f2b4dade8927c91d646e85fd42000e4836bd3192a553587d05b112ecbffabb14cbce9b224278483201edc9557d225ba5575dead4f79137dc67b7b5361e34fa93cd4814ff8ff8974bb162059e145910b398233577542b442a1cb77cefb6e7f43ed8ae22d16cc2b08292cf7041c7479901f46c2cbda2e907597f9fcfb63fb5ccee387a9a94c1a22bdbef2c4878
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125309);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id("CVE-2019-0039");
  script_bugtraq_id(107899);
  script_xref(name:"JSA", value:"JSA10928");

  script_name(english:"Juniper JSA10928");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10928 advisory. 

If REST API is enabled, the Junos OS login credentials are vulnerable to
brute force attacks. The high default connection limit of the REST API may
allow an attacker to brute-force passwords using advanced scripting techniques.
Additionally, administrators who do not enforce a strong password policy can
increase the likelihood of success from brute force attacks.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10928
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b019a7f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10928");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0039");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var fixes = make_array();

fixes['14.1X53'] = '14.1X53-D49';
fixes['15.1'] = '15.1F6-S12';
fixes['15.1X49'] = '15.1X49-D160';
fixes['15.1X53'] = '15.1X53-D236';
fixes['16.1'] = '16.1R3-S10';
fixes['16.1X65'] = '16.1X65-D49';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S10';
fixes['17.2'] = '17.2R1-S8';
fixes['17.3'] = '17.3R3-S2';
fixes['17.4'] = '17.4R1-S6';
fixes['18.1'] = '18.1R2-S4';
fixes['18.2'] = '18.2R1-S5';
fixes['18.2X75'] = '18.2X75-D30';
fixes['18.3'] = '18.3R1-S1';

var fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);


var override = TRUE;
var buf = junos_command_kb_item(cmd:"show configuration system services rest | display set");

if (buf)
{
  override = FALSE;
  var pattern_rest_api_http = '^set system services rest http';
  var pattern_rest_explorer = '^set system services rest enable-explorer';

  if (!junos_check_config(buf:buf, pattern:pattern_rest_api_http) &&
      !junos_check_config(buf:buf, pattern:pattern_rest_explorer))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have rest api enabled');

  # Rest API enabled but workaround setup
  # set system services rest control connection-limit 100
  var pattern_workaround  = 'set system services rest control connection-limit 100';
  if (junos_check_config(buf:buf, pattern:pattern_workaround))
  {
    audit(AUDIT_HOST_NOT, 'vulnerable as control connection-limit 100 is set enabled');
  }
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
