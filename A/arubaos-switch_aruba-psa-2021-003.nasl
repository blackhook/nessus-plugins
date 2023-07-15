#TRUSTED 49025e4e43c18d558f76d2ff0ac15b169d35f3bc47ce5b20eb75f602bcb4fc778fb50ed1fadd80c869d1180067d2e26c14b5d6d2604afec81fc2983d84e9458fc674029912fb1b0d87fe8e6597fc3c87356bc24ebb279b78e9715fe88a4940fce85ddcb1dd6944f8f9c4a739efa5ee078df75ce1c5c28598d7929576279af626e4b8aa4312f4c491245048ec5e9a6e029ceb17358493448593669cc347751624a1f7c15cb63ee54f8657d97eb284d768e7112acda02ccbd85f3feab1f382ca69afc11a83f8818ee8fc7578ffe6a2125592805078908537b1a10f1e84b91306001496e128113cb6c360fe4fc4a138a4de518423560a557724bdc77f9e614534fe24f7560b6fd76e1d97368394c744992772073f9ae0325ecaca24e57f774378abbabafa6e29875516d8d3a2fa852e0edcbc93455efe5190b1cc4e305d01f1cf3aef05786f755152affa7b73645ebdfa04f60f1a5571faf772aae4f9b898d175b42bfa244a61d000266b0fc206395604759f588227fadef2456ef845c29372ad0a2e3bcc62944555d931d75feb946e3068d399a5b698291b1b91abd282c60592dc19bec071077e884efcca36407064c5c7253083406ded31def4ce9cd0d41644c514abe35731ebf3fc0114991875a3ea4593860ca4e759b135053de8bad9ae72f83cac4d857c0b4b3351cdc379a79826d3962cd392556d79ecfb10e8ab14c09550
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150752);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2020-27337");

  script_name(english:"ArubaOS-Switch Memory Corruption Vulnerability (ARUBA-PSA-2021-003)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number the remote host is affected by a memory corruption vulnerability. An 
unauthenticated, remote host can exploit this to disclose sensitive information / memory contents or execute arbitrary 
code.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2021-003.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant ArubaOS-Switch version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:arubanetworks:arubaos-switch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_ports("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS-Switch');
var model = app_info['Model'];
if (empty_or_null(model) && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'ArubaOS-Switch', app_info.version);


var constraints = [];

if (model =~ "54[0-9]{2}R\s*zl2" || model =~ "3810M" || model =~ "2930[FM]" || model =~ "2920" || model =~ "2530")
{
  constraints = [
    {'min_version':'0.0', 'fixed_version':'16.08.0019'},
    {'min_version':'16.09', 'fixed_version':'16.09.0015'},
    {'min_version':'16.10', 'fixed_version':'16.10.0012'}
  ];
}
else if (model =~ "5400R\s*zl1")
{
  constraints = [{'fixed_version':'16.02.0032'}];
}
else if (model =~ "3800" || model =~ "2620")
{
  constraints = [{'fixed_version':'16.04.0022'}];
}
else if (model =~ "2[69]15")
{
  constraints = [{'fixed_version':'15.16.0023'}];
}
else if (model =~ "62[0-9]{2}\s*yl" || model =~ "82[0-9]{2}\s*zl")
{
  constraints = [{'fixed_version':'15.18.0024'}];
}
else if (model =~ "35[0-9]{2}(\s*yl)?")
{
  constraints = [{'fixed_version':'16.02.0032'}];
}
else if (!empty_or_null(model))
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}
else # Paranoid, no model case = flag widest possible range
{
  constraints = [
    {'min_version':'0.0', 'fixed_version':'16.08.0019'},
    {'min_version':'16.09', 'fixed_version':'16.09.0015'},
    {'min_version':'16.10', 'fixed_version':'16.10.0012'}
  ];
}

# Only vuln if IPv6 enabled.
var config = get_kb_item('Secret/Host/Aruba/show_running-config');
if (empty_or_null(config)) 
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'ArubaOS-Switch');
} 
else if (!preg(string:config, pattern:"\s*ipv6 enable", multiline:TRUE))
  audit(AUDIT_OS_CONF_NOT_VULN, app_info.app, app_info.version);

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
