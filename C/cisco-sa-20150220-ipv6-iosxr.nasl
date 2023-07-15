#TRUSTED 2b41885ee9b146d2242afc81988afd0e9f67d69a5ed2ee2ed91e874acb9384b2568deaab1995a3f04d425660ab4d3237b9778dbc4676cf62db00924b30e7d4abc56bd913983e9f87e2cec1c1722d3089262a78020658811b16477de22ae40a98232aa63e90f7743fffe43a4c3e573f2eae7a2159adaa2b9add5bdc42c041f7283ee4e763b2acc820cb509af3d009eba64366165969b4628474217dd73c45bb667d91f93eda89b3c7cf4ecd2024384040ad8e42fff8d84a5962345555b06346825bd4e31aa5e3457f1053f469832a7c4bba17784d3ac37baf0fd6631ede194513c28dd82126448be30080b215c3a1d85e5b8b128c8011b3596c7edc6632086bd7fce7df59dfa094d8ce766e9cd3656b7063ef32584799e0497f669c4a54195a056490c79b87f454748d23b3d3f798bc2b02e7960c2b6f89ec195bc7eea5ad179289145f0c752df7ff00891b26ddc8dd5beb3adb97853ada4f05337a79c190e6decf33e2b30afd87157ecf17121822642fb1b2e6dbbd22d8d74c7de09567c16a92983cfe6d7c28694b05bd697797df20fae6619faaa8f55e827fd82eb9bd2f96e457a24f066bb5f861e9da45bf6b9dbe7b53b3289ab46ab9a2e17d1d9d0475a599d94e36fb2d6d406c3091d29327427a64142a3842ba50c7430c5d2d09156e49d6ff54c012d49595371c0ba5329ccb16b1e46232f6e844d556c402aca1ab93b365
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82498);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2015-0618");
  script_bugtraq_id(72713);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq95241");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150220-ipv6");

  script_name(english:"Cisco IOS XR IPv6 Extension Header DoS (cisco-sa-20150220-ipv6)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is affected by a denial of service
vulnerability due to improper processing of malformed IPv6 packets
carrying extension headers. A remote attacker, using a specially
crafted packet, can cause a reload of the line card, resulting in a
denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150220-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a050f7b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37510");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150220-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

cbi = "CSCuq95241";
fixed_ver = "";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model   = get_kb_item("CISCO/model");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (model)
{
  if (
    tolower(model) !~ "^cisconcs(6008|6k)"
    &&
    tolower(model) !~ "^ciscocrs-?x"
  ) audit(AUDIT_HOST_NOT, "a Cisco NCS 6000 or CRS-X device");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "NCS6K"   >!< model
    &&
    "NCS6008" >!< model
    &&
    "CRS-X"   >!< model
    &&
    "CRSX"   >!< model
  ) audit(AUDIT_HOST_NOT, "a Cisco NCS 6000 or CRS-X device");
}

if (cisco_gen_ver_compare(a:version, b:"5.0.0") >= 0)
{
  # NCS 6k models
  if (
    "ncs" >< tolower(model)
    &&
    cisco_gen_ver_compare(a:version, b:"5.2.3") == -1
  )
  {
    flag++;
    fixed_ver =
      'upgrade to 5.2.3 or later, or consult' +
      '\ncisco-sa-20150220-ipv6 regarding patches.';
  }

  # CRS-X models
  if
  (
    tolower(model) =~ "crs-?x"
    &&
    cisco_gen_ver_compare(a:version, b:"5.3.0") == -1
  )
  {
    flag++;
    fixed_ver = "5.3.0";
  }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");

    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"IPv6 is enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
