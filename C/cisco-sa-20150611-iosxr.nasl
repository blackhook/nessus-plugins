#TRUSTED 204cf1ddff30057f1fdb8e3a6d8b5a11812d157bf998bf910b4e111c9be83e283e3b069f5d014cc2708f811ac8e17f7766f631fe59e3433ee93fca28100c2496a82164970e209ed20eed10ed585d324245568c156d162679a2433f2a33455e7d35ca1ca8d6708308307a3bbfcff9a2a6f611e9dc0803ae745e6b4eecfcb6f0b50d542062cd6b6804e29a93ed2e3d1445f355e84b3d33ec64586ea250278e270bf8b13ace1184c5d2171974746ded119a5bfd5269660b12d3fccfb877e42ffeb4a58b82c7834bc6db0d79c08888a51064fe80db759dd69d3a28732dd1dc87ae4fb3cd425d6c9727042e5e400d894c7c806a8d8a51e80e02a4d3456f1c0e0314458b689ed968b222e19f4ac4264e35244e1623c47c851ad7e9dc04c3720412df9980bff7517264fead04ffbd2692b7e5b6d829e5fd29c90f7922ce8a2df91d0a6997298f4218b8438cd6605ac6ed8e2779f0a813424c8b9c4b96a29a6d5b40757e2cfc11196fb95fbe708ca92aaa630ab55b2006c44348b902d23f8b2d06c40595e6e1e3ce55546f7c03938536937882d5ce4cf3fa6fc6bcede205e5c9e54202083089b5f03cbf0f00f6b6662bb36de3d10467df137fde854dcf9990e1049cfcd20cdac02588c88162a3d7fa70b8b2730ec8b64be5bbbc106b1537b4cdecb6b24cc07430d23b331e852bd7deb2703ea5bb077db36c2779296605c5fb068d02b637
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84287);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2015-0769");
  script_bugtraq_id(75155);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx03546");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150611-iosxr");

  script_name(english:"Cisco IOS XR Software Crafted IPv6 Packet DoS (cisco-sa-20150611-iosxr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is affected by a denial of service
vulnerability due to improper processing of IPv6 packets carrying
extension headers that are otherwise valid but are unlikely to occur
during normal operation. A remote attacker, using a specially crafted
packet, can cause a reload of the line card, resulting in a denial of
service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150611-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42990bf4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150611-iosxr.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

cbi = "CSCtx03546";
fixed_ver = "";
reason = "";

# Cisco SMUs per version (where available)
pies = make_array(
  '4.1.0', 'hfr-px-4.1.0.CSCtx03546',
  '4.1.1', 'hfr-px-4.1.1.CSCtx03546',
  '4.1.2', 'hfr-px-4.1.2.CSCtx03546',
  '4.2.0', 'hfr-px-4.2.0.CSCtx03546'
);

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model   = get_kb_item("CISCO/model");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (model)
{
  if (tolower(model) !~ "^ciscocrs-3($|[^0-9])")
    audit(AUDIT_HOST_NOT, "a Cisco CRS-3 device");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (tolower(model) !~ "^cisco crs-3($|[^0-9])")
    audit(AUDIT_HOST_NOT, "a Cisco CRS-3 device");
}

# set our fixed version based on the version detected
if (version =~ "^4\.0\.[1-4]")
{
  flag++;
  fixed_ver = "4.2.1";
}
else if (!isnull(pies[version]))
{
  flag++;
  fixed_ver = version + " with patch " + pies[version];
  if (get_kb_item("Host/local_checks_enabled"))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_install_package_all", "show install package all");
    if (check_cisco_result(buf))
    {
      if (pies[version] >< buf)
        audit(AUDIT_HOST_NOT, "affected since patch "+pies[version]+" is installed");
    }
    else if (cisco_needs_enable(buf)) override = 1;
  }
}

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
  if (check_cisco_result(buf))
  {
    # if we have an affected card
    if (preg(multiline:TRUE, pattern:"CRS-MSC-140G", string:buf) ||
        preg(multiline:TRUE, pattern:"CRS-FP140", string:buf) ||
        preg(multiline:TRUE, pattern:"CRS-LSP", string:buf))
    {
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"IPv6 is enabled", string:buf2))
        {
          # and we have ipv6 enabled
          flag = 1;
        }
        else reason = " since IPv6 isn't enabled";
      }
      else if (cisco_needs_enable(buf2))
      {
        flag = 1;
        override = 1;
      }
    }
    else reason = " since an affected line card is not installed on the chassis";
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
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
else audit(AUDIT_HOST_NOT, "affected" + reason);
