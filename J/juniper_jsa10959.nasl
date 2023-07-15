#TRUSTED 0c1513a4168e772d6a59af4c6469a06e4021d50021e7208ff1afc4ce1354293225b33b18aceff21cea695d31de25181b4c841fc1bf515e0c0a2f0f7fb86f25c270199e6a08c0d4337c06809a7f2fc074be4b013ed6fddb209a1af12f9886e6f76c2ff7192d575ed41ac1948a6fa785319447ad8c20bf207ab46ef9f386596696850700ee6de6c26fe5ed37a256bd7a7c43ca5bd27d990aaa36a2f6ea16aa4b367a4665822608867d792589c766c4a13cc870cffc34b1c6016d736978434effc9b5a862579c43e517d1b1f967a5cdb0b9a4524ae6404549cdde83e34e625f11009ae63b446966a79f10499a051149fee269c0f5002de977a3b7ff5626d9fd9b705df06b3f93a3676f7018b2aad876b8737eb4e827aec4b5741dc16c22a699254f3d6a35353c50efd8bb31d059504be29cc702ec2ba3f50acb6402a82ce9c35bf8cdcd18e8236c416be8f712d8d29dc3ec54c956fdacb0eaaaadfec822854019010698fa95b96fc6bebb5ba907007fac1c4965d29330738dfb7632bb685ef5be32634b5ecf81206093db5c237ee21647ffdb3b2e9b6016ecb113e47615f1b73a86e6ba39bc6e56a27322f56799432b63130396ff6259b00d3ee537ba4977bde02d60169d7a367b4d315cefdc82e45f77a96e9506dd79201b9d164e2087c0660c060b45f8c42aa7dfaa72b6c5f0210ad7a7fccbcf291b19204a479d3bdfa7585add
# 
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132075);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0060");
  script_xref(name:"JSA", value:"JSA10959");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: processing of specific transit IP packets in flowd, leading to Denial of Service (JSA10959)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 15.1X49-D171 or 18.4R2. It is, therefore, affected by a
vulnerability as referenced in the JSA10959 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10959");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10959");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0060");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("misc_func.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

tun = junos_command_kb_item(cmd:'show security ipsec sa');
found_tunnels = pregmatch(pattern: "Total active tunnels: ([1-9]+)", string: tun);
if (empty_or_null(found_tunnels))
   audit(AUDIT_OS_CONF_NOT_VULN, 'Junos' + ver);

fixes["15.1X49"] = "15.1X49-D171";
fixes["18.2"] = "18.2R2-S1";
fixes["18.4"] = "18.4R2";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
