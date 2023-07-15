#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165181);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2022-26858",
    "CVE-2022-26859",
    "CVE-2022-26860",
    "CVE-2022-26861"
  );
  script_xref(name:"IAVA", value:"2022-A-0359");

  script_name(english:"Dell Client BIOS Multiple Vulnerabilities (DSA-2022-224)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, there, is affected by multiple vulnerabilities.

  - Dell BIOS versions contain a stack-based buffer overflow vulnerability. A local attacker could exploit
    this vulnerability by sending malicious input via SMI to bypass security checks resulting in arbitrary
    code execution in SMM. (CVE-2022-26860)

  - Dell BIOS versions contain an Insecure Automated Optimization vulnerability. A local authenticated
    malicious user could exploit this vulnerability by sending malicious input via SMI to obtain arbitrary
    code execution during SMM. (CVE-2022-26861)

  - Dell BIOS versions contain an Improper Authentication vulnerability. A locally authenticated malicious
    user could potentially exploit this vulnerability by sending malicious input to an SMI in order to bypass
    security controls. (CVE-2022-26858)

  - Dell BIOS contains a race condition vulnerability. A local attacker could exploit this vulnerability by
    sending malicious input via SMI in order to bypass security checks during SMM. (CVE-2022-26859)

Please see the included Dell Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-ie/000202194/dsa-2022-224");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26860");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-26861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_wmi.nbin");
  script_require_keys("BIOS/Model", "BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_name = 'Dell Inc.';
var app_info = vcf::dell_bios_win::get_app_info(app:app_name);
var model = app_info['model'];

var fix = '';
# Check model
if (model)
{
  if (model == 'Alienware m15 R6') fix = '1.8.0';
  else if (model == 'ChengMing 3980') fix = '2.21.0';
  else if (model == 'ChengMing 3988') fix = '1.9.0';
  else if (model == 'ChengMing 3990') fix = '1.8.2';
  else if (model == 'ChengMing 3991') fix = '1.8.2';
  else if (model == 'Dell G15 5510') fix = '1.8.0';
  else if (model == 'Dell G15 5511') fix = '1.9.0';
  else if (model == 'Dell G3 15 3590') fix = '1.16.0';
  else if (model == 'Dell G3 3500') fix = '1.12.0';
  else if (model == 'Dell G3 3579') fix = '1.19.0';
  else if (model == 'Dell G5 15 5587') fix = '1.19.0';
  else if (model == 'Dell G5 15 5590') fix = '1.18.0';
  else if (model == 'Dell G5 5000') fix = '1.5.1';
  else if (model == 'Dell G5 5090') fix = '1.12.0';
  else if (model == 'Dell G5 5500') fix = '1.12.0';
  else if (model == 'Dell G7 15 7500') fix = '1.12.0';
  else if (model == 'Dell G7 15 7588') fix = '1.19.0';
  else if (model == 'Dell G7 17 7700') fix = '1.12.0';
  else if (model == 'Dell G7 17 7790') fix = '1.18.0';
  else if (model == 'Dell Latitude 3480') fix = '1.19.1';
  else if (model == 'Dell Latitude 3580') fix = '1.19.1';
  else if (model == 'Edge Gateway 3000 series') fix = '1.8.0';
  else if (model == 'Edge Gateway 5000') fix = '1.18.0';
  else if (model == 'Embedded Box PC 3000') fix = '1.14.0';
  else if (model == 'Embedded Box PC 5000') fix = '1.15.0';
  else if (model == 'Inspiron 13 5378 2-in-1') fix = '1.36.0';
  else if (model == 'Inspiron 13 5379 2-in-1') fix = '1.19.0';
  else if (model == 'Inspiron 13 7378 2-in-1') fix = '1.36.0';
  else if (model == 'Inspiron 14 3467') fix = '2.18.0';
  else if (model == 'Inspiron 14 3476') fix = '1.16.0';
  else if (model == 'Inspiron 15 3567') fix = '2.18.0';
  else if (model == 'Inspiron 15 5566') fix = '1.17.0';
  else if (model == 'Inspiron 15 5578 2-in-1') fix = '1.36.0';
  else if (model == 'Inspiron 15 5579 2-in-1') fix = '1.19.0';
  else if (model == 'Inspiron 15 5582 2-in-1') fix = '2.13.0';
  else if (model == 'Inspiron 15 7572') fix = '1.10.0';
  else if (model == 'Inspiron 15 Gaming 7577') fix = '1.16.0';
  else if (model == 'Inspiron 17 7773 2-in-1') fix = '1.19.0';
  else if (model == 'Inspiron 3470') fix = '2.21.0';
  else if (model == 'Inspiron 3471') fix = '1.9.0';
  else if (model == 'Inspiron 3480') fix = '1.17.0';
  else if (model == 'Inspiron 3481') fix = '1.16.0';
  else if (model == 'Inspiron 3490') fix = '1.16.0';
  else if (model == 'Inspiron 3493') fix = '1.19.0';
  else if (model == 'Inspiron 3501') fix = '1.11.0';
  else if (model == 'Inspiron 3511') fix = '1.8.0';
  else if (model == 'Inspiron 3576') fix = '1.16.0';
  else if (model == 'Inspiron 3580') fix = '1.17.0';
  else if (model == 'Inspiron 3581') fix = '1.16.0';
  else if (model == 'Inspiron 3590') fix = '1.16.0';
  else if (model == 'Inspiron 3593') fix = '1.19.0';
  else if (model == 'Inspiron 3670') fix = '2.21.0';
  else if (model == 'Inspiron 3671') fix = '1.9.0';
  else if (model == 'Inspiron 3780') fix = '1.17.0';
  else if (model == 'Inspiron 3781') fix = '1.16.0';
  else if (model == 'Inspiron 3790') fix = '1.16.0';
  else if (model == 'Inspiron 3793') fix = '1.19.0';
  else if (model == 'Inspiron 3880') fix = '1.8.2';
  else if (model == 'Inspiron 3881') fix = '1.8.3';
  else if (model == 'Inspiron 3891') fix = '1.4.1';
  else if (model == 'Inspiron 3910') fix = '1.1.66';
  else if (model == 'Inspiron 5300') fix = '1.10.0';
  else if (model == 'Inspiron 5301') fix = '1.12.0';
  else if (model == 'Inspiron 5310') fix = '2.6.1';
  else if (model == 'Inspiron 5370') fix = '1.21.0';
  else if (model == 'Inspiron 5390') fix = '1.15.0';
  else if (model == 'Inspiron 5391') fix = '1.16.0';
  else if (model == 'Inspiron 5400') fix = '1.8.0';
  else if (model == 'Inspiron 5400 2-in-1') fix = '1.10.0';
  else if (model == 'Inspiron 5401') fix = '1.10.0';
  else if (model == 'Inspiron 5401 AIO') fix = '1.8.0';
  else if (model == 'Inspiron 5402') fix = '1.9.0';
  else if (model == 'Inspiron 5406 2-in-1') fix = '1.11.1';
  else if (model == 'Inspiron 5408') fix = '1.10.0';
  else if (model == 'Inspiron 5409') fix = '1.9.0';
  else if (model == 'Inspiron 5410') fix = '2.6.1';
  else if (model == 'Inspiron 5410 2-in-1') fix = '2.6.1';
  else if (model == 'Inspiron 5480') fix = '2.13.0';
  else if (model == 'Inspiron 5481 2-in-1') fix = '2.13.0';
  else if (model == 'Inspiron 5482') fix = '2.13.0';
  else if (model == 'Inspiron 5490') fix = '1.17.0';
  else if (model == 'Inspiron 5490 All-in-One') fix = '1.13.0';
  else if (model == 'Inspiron 5491 2-in-1') fix = '1.13.0';
  else if (model == 'Inspiron 5493') fix = '1.19.0';
  else if (model == 'Inspiron 5494') fix = '1.16.0';
  else if (model == 'Inspiron 5498') fix = '1.17.0';
  else if (model == 'Inspiron 5501') fix = '1.10.0';
  else if (model == 'Inspiron 5502') fix = '1.9.0';
  else if (model == 'Inspiron 5508') fix = '1.10.0';
  else if (model == 'Inspiron 5509') fix = '1.9.0';
  else if (model == 'Inspiron 5510') fix = '2.6.1';
  else if (model == 'Inspiron 5570') fix = '1.8.0';
  else if (model == 'Inspiron 5580') fix = '2.13.0';
  else if (model == 'Inspiron 5583') fix = '1.17.0';
  else if (model == 'Inspiron 5584') fix = '1.17.0';
  else if (model == 'Inspiron 5590') fix = '1.17.0';
  else if (model == 'Inspiron 5591 2-in-1') fix = '1.13.0';
  else if (model == 'Inspiron 5593') fix = '1.19.0';
  else if (model == 'Inspiron 5594') fix = '1.16.0';
  else if (model == 'Inspiron 5598') fix = '1.17.0';
  else if (model == 'Inspiron 5770') fix = '1.8.0';
  else if (model == 'Inspiron 7000') fix = '1.16.0';
  else if (model == 'Inspiron 7300') fix = '1.12.0';
  else if (model == 'Inspiron 7300 2-in-1') fix = '1.6.0';
  else if (model == 'Inspiron 7306 2-in-1') fix = '1.11.1';
  else if (model == 'Inspiron 7370') fix = '1.22.0';
  else if (model == 'Inspiron 7373 2-in-1') fix = '1.22.0';
  else if (model == 'Inspiron 7380') fix = '1.16.0';
  else if (model == 'Inspiron 7386') fix = '1.13.0';
  else if (model == 'Inspiron 7390') fix = '1.16.0';
  else if (model == 'Inspiron 7391') fix = '1.14.0';
  else if (model == 'Inspiron 7400') fix = '1.12.0';
  else if (model == 'Inspiron 7472') fix = '1.10.0';
  else if (model == 'Inspiron 7490') fix = '1.11.0';
  else if (model == 'Inspiron 7500') fix = '1.11.0';
  else if (model == 'Inspiron 7500 2-in-1') fix = '1.6.0';
  else if (model == 'Inspiron 7501') fix = '1.11.0';
  else if (model == 'Inspiron 7506 2-in-1') fix = '1.11.1';
  else if (model == 'Inspiron 7510') fix = '1.4.0';
  else if (model == 'Inspiron 7570') fix = '1.22.0';
  else if (model == 'Inspiron 7573 2-in-1') fix = '1.22.0';
  else if (model == 'Inspiron 7580') fix = '1.16.0';
  else if (model == 'Inspiron 7586') fix = '1.13.0';
  else if (model == 'Inspiron 7590') fix = '1.13.0';
  else if (model == 'Inspiron 7591') fix = '1.13.0';
  else if (model == 'Inspiron 7610') fix = '1.4.0';
  else if (model == 'Inspiron 7700 AIO') fix = '1.8.0';
  else if (model == 'Inspiron 7706 2-in-1') fix = '1.11.1';
  else if (model == 'Inspiron 7786') fix = '1.13.0';
  else if (model == 'Inspiron 7790') fix = '1.13.0';
  else if (model == 'Inspiron 7791') fix = '1.14.0';
  else if (model == 'Inspiron 5491 AIO') fix = '1.13.0';
  else if (model == 'Latitude 13 3380') fix = '1.17.1';
  else if (model == 'Latitude 3120') fix = '1.6.0';
  else if (model == 'Latitude 3180') fix = '1.18.0';
  else if (model == 'Latitude 3189') fix = '1.18.0';
  else if (model == 'Latitude 3190') fix = '1.18.0';
  else if (model == 'Latitude 3190 2-in-1') fix = '1.18.0';
  else if (model == 'Latitude 3300') fix = '1.14.0';
  else if (model == 'Latitude 3301') fix = '1.19.0';
  else if (model == 'Latitude 3310') fix = '1.13.0';
  else if (model == 'Latitude 3310 2-in-1') fix = '1.12.0';
  else if (model == 'Latitude 3320') fix = '1.8.2';
  else if (model == 'Latitude 3379') fix = '1.0.33';
  else if (model == 'Latitude 3390') fix = '1.18.1';
  else if (model == 'Latitude 3400') fix = '1.21.0';
  else if (model == 'Latitude 3410') fix = '1.12.0';
  else if (model == 'Latitude 3420') fix = '1.14.1';
  else if (model == 'Latitude 3470') fix = '1.23.0';
  else if (model == 'Latitude 3490') fix = '1.18.0';
  else if (model == 'Latitude 3500') fix = '1.21.0';
  else if (model == 'Latitude 3510') fix = '1.12.0';
  else if (model == 'Latitude 3520') fix = '1.14.1';
  else if (model == 'Latitude 3570') fix = '1.23.0';
  else if (model == 'Latitude 3590') fix = '1.18.0';
  else if (model == 'Latitude 5175') fix = '1.13.0';
  else if (model == 'Latitude 5179') fix = '1.13.0';
  else if (model == 'Latitude 5280') fix = '1.23.1';
  else if (model == 'Latitude 5285 2-in-1') fix = '1.16.0';
  else if (model == 'Latitude 5288') fix = '1.23.1';
  else if (model == 'Latitude 5289') fix = '1.26.1';
  else if (model == 'Latitude 5290') fix = '1.20.0';
  else if (model == 'Latitude 5290 2-in-1') fix = '1.19.0';
  else if (model == 'Latitude 5300') fix = '1.19.0';
  else if (model == 'Latitude 5300 2-in-1') fix = '1.19.0';
  else if (model == 'Latitude 5310') fix = '1.10.1';
  else if (model == 'Latitude 5310 2-in-1') fix = '1.10.1';
  else if (model == 'Latitude 5320') fix = '1.15.2';
  else if (model == 'Latitude 5400') fix = '1.15.0';
  else if (model == 'Latitude 5401') fix = '1.17.0';
  else if (model == 'Latitude 5410') fix = '1.10.0';
  else if (model == 'Latitude 5411') fix = '1.10.0';
  else if (model == 'Latitude 5414 Rugged') fix = '1.33.0';
  else if (model == 'Latitude 5420') fix = '1.15.1';
  else if (model == 'Latitude 5420 Rugged') fix = '1.16.0';
  else if (model == 'Latitude 5424 Rugged') fix = '1.16.0';
  else if (model == 'Latitude 5480') fix = '1.23.1';
  else if (model == 'Latitude 5488') fix = '1.23.1';
  else if (model == 'Latitude 5490') fix = '1.20.0';
  else if (model == 'Latitude 5491') fix = '1.18.0';
  else if (model == 'Latitude 5495') fix = '1.6.0';
  else if (model == 'Latitude 5500') fix = '1.15.0';
  else if (model == 'Latitude 5501') fix = '1.17.0';
  else if (model == 'Latitude 5510') fix = '1.10.0';
  else if (model == 'Latitude 5511') fix = '1.10.0';
  else if (model == 'Latitude 5520') fix = '1.15.2';
  else if (model == 'Latitude 5521') fix = '1.8.0';
  else if (model == 'Latitude 5580') fix = '1.23.1';
  else if (model == 'Latitude 5590') fix = '1.20.0';
  else if (model == 'Latitude 5591') fix = '1.18.0';
  else if (model == 'Latitude 7200 2-in-1') fix = '1.16.1';
  else if (model == 'Latitude 7210 2-in-1') fix = '1.11.0';
  else if (model == 'Latitude 7212 Rugged Extreme Tablet') fix = '1.37.0';
  else if (model == 'Latitude 7214 Rugged Extreme') fix = '1.33.0';
  else if (model == 'Latitude 7220 Rugged Extreme Tablet') fix = '1.17.0';
  else if (model == 'Latitude 7220EX Rugged Extreme Tablet') fix = '1.17.0';
  else if (model == 'Latitude 7275 2-in-1') fix = '1.13.0';
  else if (model == 'Latitude 7280') fix = '1.24.1';
  else if (model == 'Latitude 7285 2-in-1') fix = '1.14.0';
  else if (model == 'Latitude 7290') fix = '1.23.0';
  else if (model == 'Latitude 7300') fix = '1.17.0';
  else if (model == 'Latitude 7310') fix = '1.11.0';
  else if (model == 'Latitude 7320') fix = '1.14.1';
  else if (model == 'Latitude 7320 Detachable') fix = '1.9.0';
  else if (model == 'Latitude 7370') fix = '1.27.3';
  else if (model == 'Latitude 7380') fix = '1.24.1';
  else if (model == 'Latitude 7389') fix = '1.26.1';
  else if (model == 'Latitude 7390') fix = '1.23.0';
  else if (model == 'Latitude 7390 2-in-1') fix = '1.22.0';
  else if (model == 'Latitude 7400') fix = '1.17.0';
  else if (model == 'Latitude 7400 2-in-1') fix = '1.15.1';
  else if (model == 'Latitude 7410') fix = '1.11.0';
  else if (model == 'Latitude 7414 Rugged Extreme') fix = '1.33.0';
  else if (model == 'Latitude 7420') fix = '1.14.1';
  else if (model == 'Latitude 7424 Rugged Extreme') fix = '1.16.0';
  else if (model == 'Latitude 7480') fix = '1.24.1';
  else if (model == 'Latitude 7490') fix = '1.23.0';
  else if (model == 'Latitude 7520') fix = '1.14.1';
  else if (model == 'Latitude 9410') fix = '1.11.0';
  else if (model == 'Latitude 9420') fix = '1.8.0';
  else if (model == 'Latitude 9510') fix = '1.9.0';
  else if (model == 'Latitude 9520') fix = '1.10.1';
  else if (model == 'Latitude E5270') fix = '1.29.4';
  else if (model == 'Latitude E5470') fix = '1.29.4';
  else if (model == 'Latitude E5570') fix = '1.29.4';
  else if (model == 'Latitude E7270') fix = '1.32.4';
  else if (model == 'Latitude E7470') fix = '1.32.4';
  else if (model == 'Latitude Rugged 5430') fix = '1.4.1';
  else if (model == 'Latitude Rugged 7330') fix = '1.4.1';
  else if (model == 'Latitude 5421') fix = '1.10.0';
  else if (model == 'OptiPlex 3040') fix = '1.18.1';
  else if (model == 'OptiPlex 3046') fix = '1.15.0';
  else if (model == 'OptiPlex 3050') fix = '1.19.0';
  else if (model == 'OptiPlex 3050 AIO') fix = '1.20.0';
  else if (model == 'OptiPlex 3060') fix = '1.17.0';
  else if (model == 'OptiPlex 3070') fix = '1.12.0';
  else if (model == 'OptiPlex 3080') fix = '2.8.1';
  else if (model == 'OptiPlex 3090') fix = '2.1.1';
  else if (model == 'OptiPlex 3090 Ultra') fix = '1.7.0';
  else if (model == 'OptiPlex 3240 All-in-One') fix = '1.15.0';
  else if (model == 'OptiPlex 3280 AIO') fix = '1.11.0';
  else if (model == 'OptiPlex 5040') fix = '1.21.0';
  else if (model == 'OptiPlex 5050') fix = '1.19.0';
  else if (model == 'OptiPlex 5055 A-Serial') fix = '1.6.2';
  else if (model == 'OptiPlex 5055 MT, SFF') fix = '1.6.1';
  else if (model == 'OptiPlex 5055 Ryzen CPU') fix = '1.6.1';
  else if (model == 'OptiPlex 5060') fix = '1.17.0';
  else if (model == 'OptiPlex 5070') fix = '1.12.0';
  else if (model == 'OptiPlex 5080') fix = '1.8.2';
  else if (model == 'OptiPlex 5090') fix = '1.4.3';
  else if (model == 'OptiPlex 5250') fix = '1.20.0';
  else if (model == 'OptiPlex 5260 AIO') fix = '1.17.0';
  else if (model == 'OptiPlex 5270 All-in-One') fix = '1.12.0';
  else if (model == 'OptiPlex 5480 AIO') fix = '1.12.0';
  else if (model == 'OptiPlex 5490 AIO') fix = '1.7.0';
  else if (model == 'OptiPlex 7040') fix = '1.22.0';
  else if (model == 'OptiPlex 7050') fix = '1.19.0';
  else if (model == 'OptiPlex 7060') fix = '1.17.0';
  else if (model == 'OptiPlex 7070') fix = '1.12.0';
  else if (model == 'OptiPlex 7070 Ultra') fix = '1.11.1';
  else if (model == 'OptiPlex 7071') fix = '1.12.0';
  else if (model == 'OptiPlex 7080') fix = '1.8.2';
  else if (model == 'OptiPlex 7090') fix = '1.6.1';
  else if (model == 'OptiPlex 7090 Ultra') fix = '1.7.2';
  else if (model == 'OptiPlex 7440 AIO') fix = '1.18.0';
  else if (model == 'OptiPlex 7450') fix = '1.20.0';
  else if (model == 'OptiPlex 7460 AIO') fix = '1.17.0';
  else if (model == 'OptiPlex 7470 AIO') fix = '1.12.0';
  else if (model == 'OptiPlex 7480 AIO') fix = '1.12.0';
  else if (model == 'OptiPlex 7490 AIO') fix = '1.7.0';
  else if (model == 'OptiPlex 7760 AIO') fix = '1.17.0';
  else if (model == 'OptiPlex 7770 AIO') fix = '1.12.0';
  else if (model == 'OptiPlex 7780 AIO') fix = '1.12.0';
  else if (model == 'OptiPlex XE3') fix = '1.17.0';
  else if (model == 'Precision 3240 Compact') fix = '1.9.1';
  else if (model == 'Precision 3420 Tower') fix = '2.20.0';
  else if (model == 'Precision 3430 Tower') fix = '1.17.0';
  else if (model == 'Precision 3431 Tower') fix = '1.12.0';
  else if (model == 'Precision 3440') fix = '1.8.2';
  else if (model == 'Precision 3450') fix = '1.4.2';
  else if (model == 'Precision 3510') fix = '1.29.4';
  else if (model == 'Precision 3520') fix = '1.23.1';
  else if (model == 'Precision 3530') fix = '1.18.0';
  else if (model == 'Precision 3540') fix = '1.15.0';
  else if (model == 'Precision 3541') fix = '1.17.0';
  else if (model == 'Precision 3550') fix = '1.10.0';
  else if (model == 'Precision 3551') fix = '1.10.0';
  else if (model == 'Precision 3560') fix = '1.15.2';
  else if (model == 'Precision 3561') fix = '1.8.0';
  else if (model == 'Precision 3620 Tower') fix = '2.20.0';
  else if (model == 'Precision 3630 Tower') fix = '2.12.0';
  else if (model == 'Precision 3640 Tower') fix = '1.11.1';
  else if (model == 'Precision 3650 Tower') fix = '1.7.0';
  else if (model == 'Precision 3930 Rack') fix = '2.16.1';
  else if (model == 'Precision 5510') fix = '1.20.0';
  else if (model == 'Precision 5520') fix = '1.26.0';
  else if (model == 'Precision 5530') fix = '1.23.0';
  else if (model == 'Precision 5530 2-in-1') fix = '1.17.8';
  else if (model == 'Precision 5540') fix = '1.15.0';
  else if (model == 'Precision 5550') fix = '1.12.0';
  else if (model == 'Precision 5560') fix = '1.7.0';
  else if (model == 'Precision 5720 AIO') fix = '2.13.0';
  else if (model == 'Precision 5750') fix = '1.12.0';
  else if (model == 'Precision 5760') fix = '1.6.0';
  else if (model == 'Precision 5820 Tower') fix = '2.14.0';
  else if (model == 'Precision 7520') fix = '1.23.1';
  else if (model == 'Precision 7530') fix = '1.19.0';
  else if (model == 'Precision 7540') fix = '1.17.0';
  else if (model == 'Precision 7550') fix = '1.12.0';
  else if (model == 'Precision 7560') fix = '1.10.1';
  else if (model == 'Precision 7710') fix = '1.25.3';
  else if (model == 'Precision 7720') fix = '1.23.1';
  else if (model == 'Precision 7730') fix = '1.19.0';
  else if (model == 'Precision 7740') fix = '1.17.0';
  else if (model == 'Precision 7750') fix = '1.12.0';
  else if (model == 'Precision 7760') fix = '1.10.1';
  else if (model == 'Precision 7820 Tower') fix = '2.18.0';
  else if (model == 'Precision 7920 Tower') fix = '2.18.0';
  else if (model == 'Vostro 15 7570') fix = '1.16.0';
  else if (model == 'Vostro 15 7580') fix = '1.19.0';
  else if (model == 'Vostro 3070') fix = '2.21.0';
  else if (model == 'Vostro 3267') fix = '1.19.0';
  else if (model == 'Vostro 3268') fix = '1.19.0';
  else if (model == 'Vostro 3400') fix = '1.11.0';
  else if (model == 'Vostro 3401') fix = '1.11.0';
  else if (model == 'Vostro 3468 14') fix = '3.11.0';
  else if (model == 'Vostro 3470') fix = '2.21.0';
  else if (model == 'Vostro 3471') fix = '1.9.0';
  else if (model == 'Vostro 3478 14') fix = '1.16.0';
  else if (model == 'Vostro 3480') fix = '1.17.0';
  else if (model == 'Vostro 3481') fix = '1.16.0';
  else if (model == 'Vostro 3490') fix = '1.16.0';
  else if (model == 'Vostro 3500') fix = '1.11.0';
  else if (model == 'Vostro 3501') fix = '1.11.0';
  else if (model == 'Vostro 3510') fix = '1.8.0';
  else if (model == 'Vostro 3568 15') fix = '3.11.0';
  else if (model == 'Vostro 3578 15') fix = '1.16.0';
  else if (model == 'Vostro 3580') fix = '1.17.0';
  else if (model == 'Vostro 3581') fix = '1.16.0';
  else if (model == 'Vostro 3583') fix = '1.17.0';
  else if (model == 'Vostro 3584') fix = '1.16.0';
  else if (model == 'Vostro 3590') fix = '1.16.0';
  else if (model == 'Vostro 3660') fix = '1.19.0';
  else if (model == 'Vostro 3667') fix = '1.19.0';
  else if (model == 'Vostro 3668') fix = '1.19.0';
  else if (model == 'Vostro 3669') fix = '1.19.0';
  else if (model == 'Vostro 3670') fix = '2.21.0';
  else if (model == 'Vostro 3671') fix = '1.9.0';
  else if (model == 'Vostro 3681') fix = '2.8.2';
  else if (model == 'Vostro 3690') fix = '1.4.1';
  else if (model == 'Vostro 3710') fix = '1.1.66';
  else if (model == 'Vostro 3881') fix = '2.8.2';
  else if (model == 'Vostro 3888') fix = '2.8.2';
  else if (model == 'Vostro 3890') fix = '1.4.1';
  else if (model == 'Vostro 3910') fix = '1.1.66';
  else if (model == 'Vostro 5090') fix = '1.12.0';
  else if (model == 'Vostro 5300') fix = '1.10.0';
  else if (model == 'Vostro 5301') fix = '1.12.0';
  else if (model == 'Vostro 5310') fix = '2.6.1';
  else if (model == 'Vostro 5370') fix = '1.21.0';
  else if (model == 'Vostro 5390') fix = '1.15.0';
  else if (model == 'Vostro 5391') fix = '1.16.0';
  else if (model == 'Vostro 5401') fix = '1.10.0';
  else if (model == 'Vostro 5402') fix = '1.9.0';
  else if (model == 'Vostro 5410') fix = '2.6.1';
  else if (model == 'Vostro 5468 14') fix = '1.18.0';
  else if (model == 'Vostro 5471') fix = '1.21.0';
  else if (model == 'Vostro 5481') fix = '2.13.0';
  else if (model == 'Vostro 5490') fix = '1.17.0';
  else if (model == 'Vostro 5491') fix = '1.19.0';
  else if (model == 'Vostro 5501') fix = '1.10.0';
  else if (model == 'Vostro 5502') fix = '1.9.0';
  else if (model == 'Vostro 5510') fix = '2.6.1';
  else if (model == 'Vostro 5568 15') fix = '1.18.0';
  else if (model == 'Vostro 5581') fix = '2.13.0';
  else if (model == 'Vostro 5590') fix = '1.17.0';
  else if (model == 'Vostro 5591') fix = '1.19.0';
  else if (model == 'Vostro 5880') fix = '1.8.2';
  else if (model == 'Vostro 5890') fix = '1.4.0';
  else if (model == 'Vostro 7500') fix = '1.11.0';
  else if (model == 'Vostro 7510') fix = '1.4.0';
  else if (model == 'Vostro 7590') fix = '1.13.0';
  else if (model == 'Wyse 5070') fix = '1.16.0';
  else if (model == 'Wyse 5470') fix = '1.12.0';
  else if (model == 'Wyse 5470 AIO') fix = '1.14.1';
  else if (model == 'Wyse 7040 Thin Client') fix = '1.14.0';
  else if (model == 'XPS 13 9305') fix = '1.3.0';
  else if (model == 'XPS 13 7390') fix = '1.12.1';
  else if (model == 'XPS 13 7390 2-in-1') fix = '1.13.0';
  else if (model == 'XPS 13 9300') fix = '1.9.1';
  else if (model == 'XPS 13 9310') fix = '3.4.0';
  else if (model == 'XPS 13 9310 2-in-1') fix = '2.7.0';
  else if (model == 'XPS 13 9360') fix = '2.19.0';
  else if (model == 'XPS 13 9365 2-in-1') fix = '2.19.0';
  else if (model == 'XPS 13 9370') fix = '1.18.0';
  else if (model == 'XPS 13 9380') fix = '1.17.0';
  else if (model == 'XPS 15 7590') fix = '1.15.0';
  else if (model == 'XPS 15 9500') fix = '1.12.0';
  else if (model == 'XPS 15 9510') fix = '1.7.0';
  else if (model == 'XPS 15 9570') fix = '1.23.0';
  else if (model == 'XPS 15 9575 2-In-1') fix = '1.19.0';
  else if (model == 'XPS 17 9700') fix = '1.12.0';
  else if (model == 'XPS 17 9710') fix = '1.6.0';
  else if (model == 'XPS 27 7760') fix = '2.13.0';
  else if (model == 'XPS 7590') fix = '1.15.0';
  else if (model == 'XPS 8940') fix = '2.4.0';
  # Check different Tower/Rack orderings
  else if (model == 'Precision Tower 3420') fix = '2.20.0';
  else if (model == 'Precision Tower 3430') fix = '1.17.0';
  else if (model == 'Precision Tower 3431') fix = '1.12.0';
  else if (model == 'Precision Tower 3620') fix = '2.20.0';
  else if (model == 'Precision Tower 3630') fix = '2.12.0';
  else if (model == 'Precision Tower 3640') fix = '1.11.1';
  else if (model == 'Precision Tower 3650') fix = '1.7.0';
  else if (model == 'Precision Tower 5820') fix = '2.14.0';
  else if (model == 'Precision Tower 7820') fix = '2.18.0';
  else if (model == 'Precision Tower 7920') fix = '2.18.0';
  else if (model == 'Precision Rack 3930') fix = '2.16.1';
  else
  {
  audit(AUDIT_HOST_NOT, 'an affected model');
  }
}
else
{
  exit(0, 'The model of the device running the Dell BIOS could not be identified.');
}

var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
# Have a more useful audit message
app_info.app = 'Dell System BIOS for ' + model;

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

