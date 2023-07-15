#TRUSTED 54150244e7fb1cfa2c44de1161684aa878f0e899a49074832638e2aede412ab0102b83075ea2be621e47d37fe17d809eda4d62d4dccce562c4b3554f507916fe4a07a020059059360c7e6ad19ae8e2381491ca93760ade5a57d73ceac9b8685a094482b804342230efdbebc1afd3252033dfc9acb4b9818fca13693458f30366056b2dbd99c20600e7987a9d224adaaad8e90e5f84b5a9ffe151a937e97de5640746454aa2985e22751f98da6c1f365d513a6a32cd56f57654fcdc0cc55c6b6d4ceddc00e7ed0f0351fa76e7a6052ed4f8566ff89f8964a16413481b0f4e0eecf4313c5f593989757f17fcd483f6eac63ac50480440e7e11f4ab8ca8ff89553842626b6a8657e3b02ea3c1cc75f89027030497f7e40a41fb3a39a9a860a743e6b2f5a7cb19f1cbf6c8a73029082a4c957cf0f3fafc08b3ce2d12af73c0a4c06bdfdfc683ba4a0dbc17df960932ba8bfda9fc2f1e89d21a1bad1794e233a484f8b119a4b1e0770debf396799156d59c0dbde67b1f09353843ee1e74b3d0e72d80bcbcdb015e0f0b3aba1fa24ebd20783f01de607640485a73a47251025789964c1ec2c3f5cab4f332184a26d85d5b179230d2f090e4cac368e49fa6e2e3e3da93b5121001bf9dc2d70c9da3db6bc5661aeae556d7bfc896a38f37cea1f59b3e3d018ec81e19826a3f1e7db499799361db7fc4d19ef7d3b5f11191b9e9baf63312
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121644);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id("CVE-2019-0010");
  script_xref(name:"JSA", value:"JSA10910");

  script_name(english:"Junos OS: Crafted HTTP traffic may cause UTM to consume all mbufs, leading to Denial of Service (JSA10910)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. An 
SRX Series Service Gateway configured for Unified Threat Management 
(UTM) may experience a denial of service due to the receipt of 
crafted HTTP traffic.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10910");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10910.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0010");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D81';
fixes['12.3X48'] = '12.3X48-D77';
fixes['15.1X49'] = '15.1X49-D101';


fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If  Unified Threat Management (UTM) isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set security utm";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have UTM enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

