#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(178017);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-35176");
  script_xref(name:"HP", value:"HPSBPI03852");
  script_xref(name:"IAVA", value:"2023-A-0329");

  script_name(english:"HP LaserJet Printers DoS (HPSBPI03852)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a buffer overflow / denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"Certain HP LaserJet Pro print products are potentially vulnerable to Buffer Overflow and/or Denial of Service when
using the backup & restore feature through the embedded web service on the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hp.com/us-en/document/ish_8651671-8651697-16/hpsbpi03852
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a459514");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf_extras.inc');

var app_info = vcf::hp_laserjet::get_app_info(fw_rev:TRUE);

var uglyfix = '002_2322C';
# let's make the fix pretty
var fix = vcf::hp_laserjet::transform_ver(firmware:uglyfix);

# if its not one of these models, its not affected.
var affected_models = make_list(
  "W1A75A", "W1A76A", "W1A77A", "W1A81A", "W1A82A", "W1A79A", "W1A80A", "W1A78A",
  "W1Y40A", "W1Y41A", "W1Y46A", "W1Y47A", "W1Y44A", "W1Y45A", "W1Y43A", "W1A66A",
  "W1A46A", "W1A47A", "W1A48A", "W1A51A", "W1A53A", "W1A56A", "W1A63A", "W1A52A",
  "93M22A", "W1A58A", "W1A59A", "W1A60A", "W1A57A", "W1A29A", "W1A32A", "W1A30A",
  "W1A38A", "W1A34A", "W1A35A", "W1A28A", "W1A31A", "W1A33A" 
);

var constraints = [
  { 'models': affected_models, 'fixed_version': fix, 'fixed_display': uglyfix}
];

vcf::hp_laserjet::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
