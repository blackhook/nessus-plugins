#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172172);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/08");

  script_cve_id("CVE-2022-32482");

  script_name(english:"Dell Client BIOS Multiple Vulnerabilities (DSA-2022-326)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, there, is affected by an input validation
vulnerability. A local authenticated malicious user with admin privileges may potentially exploit this vulnerability in
order to modify a UEFI variable.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-ie/000205717/dsa-2022-326");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32482");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is This script is Copyright (C) 2023 202d and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  if (model == 'Alienware m15 R6') fix = '1.17.0';
  else if (model == 'Alienware m15 R7') fix = '1.10.0';
  else if (model =~ 'ChengMing 3900') fix = '1.7.3';
  else if ('G15 5510' >< model) fix = '1.16.0'; # Gx models all edited to match what is detected
  else if ('G15 5511' >< model) fix = '1.18.0';
  else if ('G15 5520' >< model) fix = '1.10.0';
  else if ('G16 7620' >< model) fix = '1.12.0';
  else if ('G3 3500' >< model) fix = '1.20.0';
  else if (model =~ 'G5 (15 )?5500') fix = '1.20.0';
  else if (model =~ 'G7 (15 )?7500') fix = '1.19.0';
  else if (model =~ 'G7 (17 )?7700') fix = '1.19.0';
  else if (model == 'Inspiron 14 5410 2-in-1') fix = '2.15.2';
  else if (model == 'Inspiron 14 Plus 7420') fix = '1.6.1';
  else if (model == 'Inspiron 15 3511') fix = '1.18.2';
  else if (model == 'Inspiron 16 Plus 7620') fix = '1.6.1';
  else if (model == 'Inspiron 3490') fix = '1.21.0';
  else if (model == 'Inspiron 3493') fix = '1.24.0';
  else if (model == 'Inspiron 3501') fix = '1.19.0';
  else if (model == 'Inspiron 3511') fix = '1.18.2';
  else if (model == 'Inspiron 3520') fix = '1.8.2';
  else if (model == 'Inspiron 3590') fix = '1.21.0';
  else if (model == 'Inspiron 3593') fix = '1.24.0';
  else if (model == 'Inspiron 3790') fix = '1.21.0';
  else if (model == 'Inspiron 3793') fix = '1.24.0';
  else if (model == 'Inspiron 3891') fix = '1.12.0';
  else if (model == 'Inspiron 3910') fix = '1.7.3';
  else if (model == 'Inspiron 5300') fix = '1.17.0';
  else if (model == 'Inspiron 5301') fix = '1.21.0';
  else if (model == 'Inspiron 5310') fix = '2.15.0';
  else if (model == 'Inspiron 5320') fix = '1.3.0';
  else if (model == 'Inspiron 5390') fix = '1.19.0';
  else if (model == 'Inspiron 5391') fix = '1.20.0';
  else if (model == 'Inspiron 5400 2-in-1') fix = '1.18.0';
  else if (model == 'Inspiron 5401') fix = '1.18.0';
  else if (model == 'Inspiron 5402') fix = '1.18.0';
  else if (model == 'Inspiron 5406 2-in-1') fix = '1.18.0';
  else if (model == 'Inspiron 5408') fix = '1.18.0';
  else if (model == 'Inspiron 5409') fix = '1.18.0';
  else if (model == 'Inspiron 5410 AIO') fix = '1.4.0';
  else if (model == 'Inspiron 5420') fix = '1.6.0';
  else if (model == 'Inspiron 5490') fix = '1.21.0';
  else if (model == 'Inspiron 5491 2-in-1') fix = '1.17.0';
  else if (model == 'Inspiron 5493') fix = '1.24.0';
  else if (model == 'Inspiron 5494') fix = '1.21.0';
  else if (model == 'Inspiron 5498') fix = '1.21.0';
  else if (model == 'Inspiron 5501') fix = '1.18.0';
  else if (model == 'Inspiron 5502') fix = '1.18.0';
  else if (model == 'Inspiron 5508') fix = '1.18.0';
  else if (model == 'Inspiron 5509') fix = '1.18.0';
  else if (model == 'Inspiron 5510') fix = '2.15.2';
  else if (model == 'Inspiron 5583') fix = '1.21.0';
  else if (model == 'Inspiron 5584') fix = '1.21.0';
  else if (model == 'Inspiron 5590') fix = '1.21.0';
  else if (model == 'Inspiron 5591 2-in-1') fix = '1.17.0';
  else if (model == 'Inspiron 5593') fix = '1.24.0';
  else if (model == 'Inspiron 5594') fix = '1.21.0';
  else if (model == 'Inspiron 5598') fix = '1.21.0';
  else if (model == 'Inspiron 5620') fix = '1.6.0';
  else if (model == 'Inspiron 7000') fix = '1.20.0';
  else if (model == 'Inspiron 7300') fix = '1.21.0';
  else if (model == 'Inspiron 7300 2-in-1') fix = '1.13.0';
  else if (model == 'Inspiron 7306 2-in-1') fix = '1.18.0';
  else if (model == 'Inspiron 7391') fix = '1.18.0';
  else if (model == 'Inspiron 7400') fix = '1.21.0';
  else if (model == 'Inspiron 7420') fix = '1.4.0';
  else if (model == 'Inspiron 7490') fix = '1.17.0';
  else if (model == 'Inspiron 7500') fix = '1.18.0';
  else if (model == 'Inspiron 7500 2-in-1 Black') fix = '1.13.0';
  else if (model == 'Inspiron 7500 2-in-1 Silver') fix = '1.18.0';
  else if (model == 'Inspiron 7501') fix = '1.18.0';
  else if (model == 'Inspiron 7506 2-in-1') fix = '1.18.0';
  else if (model == 'Inspiron 7510') fix = '1.12.0';
  else if (model == 'Inspiron 7591') fix = '1.18.0';
  else if (model == 'Inspiron 7610') fix = '1.12.0';
  else if (model == 'Inspiron 7620') fix = '1.4.0';
  else if (model == 'Inspiron 7706 2-in-1') fix = '1.18.0';
  else if (model == 'Inspiron 7710') fix = '1.4.0';
  else if (model == 'Inspiron 7791') fix = '1.18.0';
  else if (model == 'Latitude 3301') fix = '1.24.0';
  else if (model == 'Latitude 3320') fix = '1.18.2';
  else if (model == 'Latitude 3330') fix = '1.8.0';
  else if (model == 'Latitude 3400') fix = '1.26.0';
  else if (model == 'Latitude 3410') fix = '1.20.2';
  else if (model == 'Latitude 3420') fix = '1.23.2';
  else if (model == 'Latitude 3430') fix = '1.4.0';
  else if (model == 'Latitude 3500') fix = '1.26.0';
  else if (model == 'Latitude 3510') fix = '1.20.2';
  else if (model == 'Latitude 3520') fix = '1.23.2';
  else if (model == 'Latitude 3530') fix = '1.4.0';
  else if (model == 'Latitude 5320') fix = '1.24.3';
  else if (model == 'Latitude 5330') fix = '1.5.0';
  else if (model == 'Latitude 5420') fix = '1.22.0';
  else if (model == 'Latitude 5430') fix = '1.8.3';
  else if (model == 'Latitude 5431') fix = '1.7.0';
  else if (model == 'Latitude 5521') fix = '1.17.3';
  else if (model == 'Latitude 5530') fix = '1.5.0';
  else if (model == 'Latitude 5531') fix = '1.6.0';
  else if (model == 'Latitude 7320') fix = '1.20.0';
  else if (model == 'Latitude 7320 Detachable') fix = '1.17.2';
  else if (model == 'Latitude 7330') fix = '1.6.0';
  else if (model == 'Latitude 7420') fix = '1.20.0';
  else if (model == 'Latitude 7430') fix = '1.6.0';
  else if (model == 'Latitude 7520') fix = '1.20.0';
  else if (model == 'Latitude 7530') fix = '1.6.0';
  else if (model == 'Latitude 9330') fix = '1.3.3';
  else if (model == 'Latitude 9420') fix = '1.16.2';
  else if (model == 'Latitude 9430') fix = '1.6.0';
  else if (model == 'Latitude 9520') fix = '1.17.0';
  else if (model == 'Latitude 5430 Rugged') fix = '1.12.0'; # Rearranged per detection
  else if (model == 'Latitude 7330 Rugged') fix = '1.12.0'; # Rearranged per detection
  else if (model == 'Latitude 5421') fix = '1.15.0';
  else if (model == 'OptiPlex 3000') fix = '1.4.1';
  else if (model == 'OptiPlex 3000 Thin Client') fix = '1.5.3';
  else if (model == 'OptiPlex 3090 Ultra') fix = '1.15.0';
  else if (model == 'OptiPlex 5000') fix = '1.4.1';
  else if (model == 'OptiPlex 5090') fix = '1.12.0';
  else if (model == 'OptiPlex 5400') fix = '1.1.15';
  else if (model == 'OptiPlex 5490 AIO') fix = '1.15.0';
  else if (model == 'OptiPlex 7000') fix = '1.4.1';
  else if (model == 'OptiPlex 7000 OEM') fix = '1.4.1';
  else if (model == 'OptiPlex 7090') fix = '1.12.0';
  else if (model == 'OptiPlex 7090 Ultra') fix = '1.15.0';
  else if (model == 'OptiPlex 7400') fix = '1.1.15';
  else if (model == 'OptiPlex 7490 AIO') fix = '1.15.0';
  else if (model == 'Precision 3450') fix = '1.12.0';
  else if (model == 'Precision 3460 Small Form Factor') fix = '1.4.2';
  else if (model == 'Precision 3470') fix = '1.7.0';
  else if (model == 'Precision 3560') fix = '1.24.3';
  else if (model == 'Precision 3561') fix = '1.17.3';
  else if (model == 'Precision 3570') fix = '1.5.0';
  else if (model == 'Precision 3571') fix = '1.6.0';
  else if (model == 'Precision 3650 Tower') fix = '1.16.0';
  else if (model == 'Precision 3660') fix = '1.4.0';
  else if (model == 'Precision 5470') fix = '1.5.0';
  else if (model == 'Precision 5550') fix = '1.19.0';
  else if (model == 'Precision 5560') fix = '1.15.2';
  else if (model == 'Precision 5570') fix = '1.5.0';
  else if (model == 'Precision 5750') fix = '1.20.0';
  else if (model == 'Precision 5760') fix = '1.15.2';
  else if (model == 'Precision 5770') fix = '1.9.0';
  else if (model == 'Precision 7560') fix = '1.16.0';
  else if (model == 'Precision 7670') fix = '1.7.1';
  else if (model == 'Precision 7760') fix = '1.16.0';
  else if (model == 'Precision 7770') fix = '1.7.1';
  else if (model == 'Vostro 3400') fix = '1.19.0';
  else if (model == 'Vostro 3401') fix = '1.19.0';
  else if (model == 'Vostro 3420') fix = '1.8.2';
  else if (model == 'Vostro 3490') fix = '1.21.0';
  else if (model == 'Vostro 3500') fix = '1.19.0';
  else if (model == 'Vostro 3501') fix = '1.19.0';
  else if (model == 'Vostro 3510') fix = '1.18.2';
  else if (model == 'Vostro 3520') fix = '1.8.2';
  else if (model == 'Vostro 3590') fix = '1.21.0';
  else if (model == 'Vostro 3690') fix = '1.12.0';
  else if (model == 'Vostro 3710') fix = '1.7.3';
  else if (model == 'Vostro 3890') fix = '1.12.0';
  else if (model == 'Vostro 3910') fix = '1.7.3';
  else if (model == 'Vostro 5300') fix = '1.17.0';
  else if (model == 'Vostro 5301') fix = '1.21.0';
  else if (model == 'Vostro 5310') fix = '2.15.0';
  else if (model == 'Vostro 5390') fix = '1.19.0';
  else if (model == 'Vostro 5391') fix = '1.20.0';
  else if (model == 'Vostro 5401') fix = '1.18.0';
  else if (model == 'Vostro 5402') fix = '1.18.0';
  else if (model == 'Vostro 5410') fix = '2.15.2';
  else if (model == 'Vostro 5490') fix = '1.21.0';
  else if (model == 'Vostro 5491') fix = '1.24.0';
  else if (model == 'Vostro 5501') fix = '1.18.0';
  else if (model == 'Vostro 5502') fix = '1.18.0';
  else if (model == 'Vostro 5510') fix = '2.15.2';
  else if (model == 'Vostro 5590') fix = '1.21.0';
  else if (model == 'Vostro 5591') fix = '1.24.0';
  else if (model == 'Vostro 5620') fix = '1.6.0';
  else if (model == 'Vostro 5890') fix = '1.12.0';
  else if (model == 'Vostro 7500') fix = '1.18.0';
  else if (model == 'Vostro 7510') fix = '1.12.0';
  else if (model == 'XPS 13 9305') fix = '1.10.0';
  else if (model == 'XPS 13 7390') fix = '1.18.0';
  else if (model == 'XPS 13 7390 2-in-1') fix = '1.20.0';
  else if (model == 'XPS 13 9300') fix = '1.15.0';
  else if (model == 'XPS 13 9310') fix = '3.11.0';
  else if (model == 'XPS 13 9310 2-in-1') fix = '2.14.0';
  else if (model == 'XPS 13 9315') fix = '1.2.0';
  else if (model == 'XPS 13 9320') fix = '1.6.0';
  else if (model == 'XPS 15 9500') fix = '1.19.0';
  else if (model == 'XPS 15 9510') fix = '1.15.2';
  else if (model == 'XPS 15 9520') fix = '1.5.0';
  else if (model == 'XPS 17 9700') fix = '1.20.0';
  else if (model == 'XPS 17 9710') fix = '1.15.2';
  else if (model == 'XPS 17 9720') fix = '1.9.0';
  # Extra products for different Tower/Rack orderings
  else if (model == 'Precision Tower 3650') fix = '1.16.0';
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
