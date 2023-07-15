#TRUSTED 2357344f7eb89dd141dcc81b19d243cb4da0d6f694b1380c5e03a87a1da0ca41eb6517d4c117cd99ebb0d671ac9c1d704e546759b006d18ce1c370b9b004ff40642a8596087fa88baa926347bba16cd5ba07b7caa52fddc1db81ef741f978f27e01e660e7c2d63225fad72be18f89d80b2550959dcaadc8606dae6ba7ea18c2462a099c59ea6712d0a0014073d23107cc8e933f231319d3eb85fff54534913d68aaca2847a382423c43af4c6717b7aac4eb979f1e50ff4d5f413e607f52f0ab97049bf96755907c04047532ec8fb7d9671d4d5b286c02dbec5343b362611f0adf14bc394a14eb0491f651587ab5e9aa0f6c44a0d74f7d0bead7511ebf02eadca7126cc1f4aaca62ff885d4768882e7483081c6fe43378c3274175780a796aeda608bd4a0131b8b54e53324aad4e36fd9263137299ceb6da55ce92c86340e45d326a6e191272829e7843d6233dba9693f4a4250583d27e7a49447f708d052ab6a43cb20d595b765673f7e35ab576864cf289f51148bf684686cb697f5901ec02b65f5deacdd8deafcd6d341e71615dfd397827e619ddc9331add214ccb3d256041655bd65d7b9b248eeaebd8724b6f9971c3748a8b50c4ea877acc929a75c311dc998fe21ed167946b3b7fb7202cec3f8190f27e3bbab9259f01ea4c65db96e63fafac0e4d10d058539aaf00cdc88af4399078ed485b208bd06fc48c7d499432a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88096);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1262");
  script_xref(name:"JSA", value:"JSA10721");

  script_name(english:"Juniper Junos RTSP Packet Handling flowd DoS (JSA10721)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service vulnerability due to a
flaw in the Real Time Streaming Protocol Application Layer Gateway
(RTSP ALG) implementation. An unauthenticated, remote attacker can
exploit this, via a crafted RTSP packet, to crash the flowd daemon.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10721");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10721.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D45';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3X48'] = '12.3X48-D20';
fixes['15.1X49'] = '15.1X49-D30';

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show security alg status");
if (buf)
{
  pattern = "^\s*RTSP\s*:\s*Enabled";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the RTSP ALG is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
