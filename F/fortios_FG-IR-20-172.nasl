#TRUSTED a1c5a31ecea576522758765b3df2a1fe214b934d5aa7cf028653ba9f4b8661006d1a37b6c5601ef33e9f19299dfdf84e0070588a83d6bf48083e01ee81613cfede5d80fedf9265b08598656b3825ad8ec3678c533431cf83cef51d838f1586e719b0a88aed07787817feca3c54d682fe595442e7face6355969f0096c6da28fb2ee6f844fb129c2a0a43453e9383e924c45e79c6c40f09ba3b92e2484005cc024445f2ab505934dc0eb753f621ee25c07eb64efaa6c662b7b1a22e13baea48db434c4570c75376c59b53d1910cb1172dbe750534fe51c5a38b2274a5311637b13c6782b1838dd9603b6921c005213c2fbafc7a37d27cadae08898cda34d25bb5b686c09d401f03157c24163732c7d0c2f38516842fcd680f04e73622ff6eccfc3f20be4c60cf67ffc594e6418d0b2b225dfc73c1bf79276dc4b90edb63a4259b0e52a8d871cb8b7702e9a541441cc621c00074c1218a83a849f2a96717da22eb33caf7b269c374b195d07974b9ce2298b0a5561a8fe28da8ca5109c848031fc2142b39c354bcf0b47d3e212a8af4a8f6473b9e2328477b5167ad44671a86f054ae646495ae6d69c12fa67c0a0ba8ede898058daba41b44af225cb83be73c4b0ba5cfc89a412405bb0588b796e8a6b42dd080e0b5f29b29ccbf638b7b366e7d563c02870c757f0c56569f56b2cc87c0bbdc38bcfce06d85ad67acac160bcfdc88
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147661);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2020-15938");
  script_xref(name:"IAVA", value:"2021-A-0120-S");

  script_name(english:"Fortinet FortiOS <= 6.2.5 / 6.4 <= 6.4.2 Traffic Bypass (FG-IR-20-172)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a traffic bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior or equal to 6.2.5, or 6.4 prior to 6.4.3. It is, therefore,
affected by a traffic bypass vulnerability. When traffic other than HTTP/S (eg: SSH traffic, etc...) traverses the
FortiGate in version below 6.2.5 and below 6.4.2 on port 80/443, it is not redirected to the transparent proxy policy
for processing, as it doesn't have a valid HTTP header.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-172");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'max_version': '6.2.5', 'fixed_display' : '6.4.3' },
  {'min_version': '6.4', 'fixed_version': '6.4.3' }
];

report +=
  '\n  FortiOS is currently running a vulnerable configuration,'
  +'\n as the tunnel-non-http setting is not disabled and/or '
  +'\n unsupported-ssl is not set to block.';

workarounds = [
  {config_command:'full-configuration', config_value:'unsupported-ssl block'},
  {config_command:'full-configuration', config_value:'tunnel-non-http disable'}
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  workarounds:workarounds,
  report:report,
  not_equal:FALSE,
  all_required:TRUE
);
