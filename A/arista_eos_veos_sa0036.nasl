#TRUSTED 6249f270f70720465dbdbd35364f9899cb53158dd17f6c3fcaaff1128b8582ec39b6d495a005c1f00f412b0efd31a006b0d07243ea7329cd903c5c3efaf3c393b694cb88ccbdeee35502424c5559baa61ec0f735b6024a7df31add69228a3628a7018e2e2ed37e4c77817daa019c4ff30842d20b63c3dd8820e34103e66af59e042b51af20d9264158e5eb45929222b0d53ffb866c957e90921cf06cc8c964100318fb4ad67011e77cf2888fc85f3610d573fe764bc24b1222c8ec48e7fe078f5b48f77ed5fd5707e6301bb3d57cf09ae8a36a72af703f61082d604ef8f5ebda1c49393e4e012747bba9ac70e68aa26950100df0b6a7902c964464bda889f55de29f9bca6bb6a130c81c4446c680aba365b4ba17540f6ea593ee5e1c019fd9e6ced4ab1a31a3d22f12b21eb99c200c0ba9820956f51fc5f7b1a7ebbfbe574fba41b94501c663550f4a98fa95ad49af350fedef33bd92e5c218759c35b79d60f97de4d1201c45d1718109b05e51bb6935f69e64221396448938d29475b8e2aa81e6b7e8c4716f000294f21e56d6e760c29309c5ec87ef507cfa45fe6fad0539cc075a375fc55405fecc23d3c89beb434b09d10f4844403b7a8bfb30f42859faed81d23b5e7e8e0636d47c272d09c43cffa23cc85ebb8f465cd07dbf1f0b037c28a5b7f73f4006b677df199ea520ff924c18a88eca7fff56cebaa40a98eef4c452
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133724);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2018-5390");
  script_bugtraq_id(104976);
  script_xref(name:"CERT", value:"962459");

  script_name(english:"Arista Networks EOS/vEOS SegmentSmack TCP DoS (SA0036)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS or vEOS running on the remote device is affected by a denial of servics (DoS)
vulnerability. A flaw named SegmentSmack was found in the way the Linux kernel handles specially crafted TCP packets. An
unauthenticated, remote attacker can use this flaw to trigger time and calculation expensive calls to
tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() functions by sending specially modified packets within ongoing TCP
sessions which could lead to a CPU saturation and hence a denial of service on the system. Maintaining the denial of
service condition requires continuous two-way TCP sessions to a reachable open port, thus the attacks cannot be
performed using spoofed IP addresses.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/5721-security-advisory-36
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8af9c5b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version EOS-4.21.2.3F, EOS-4.21.0F, EOS-4.20.8M, EOS-4.19.10M, EOS-4.18.9M,
EOS-4.17.10M or later. Alternatively, apply the recommended mitigation referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Host/Arista-EOS/model");

  exit(0);
}


include('arista_eos_func.inc');

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
model = get_kb_item_or_exit('Host/Arista-EOS/model');

vmatrix = make_array();

if (model == 'vEOS')
{
  vmatrix['F'] = make_list('4.20.5');
  vmatrix['misc'] = make_list('4.20.6FX', '4.20.1FX', '4.18.0FX');
}
else
{
  vmatrix['all'] =  make_list('0.0<=4.15.99');
  vmatrix['F'] =    make_list('4.17.0<=4.17.3',
                              '4.18.0<=4.18.4.2',
                              '4.19.0<=4.19.3',
                              '4.20.0<=4.20.6');

  vmatrix['M'] =    make_list('4.16.6<=4.16.14',
                              '4.17.4<=4.17.9',
                              '4.18.5<=4.18.8',
                              '4.19.4<=4.19.9',
                              '4.20.7');
}

vmatrix['fix'] = 'Apply the vendor supplied mitigation or upgrade to EOS-4.21.2.3F / EOS-4.21.0F / EOS-4.20.8M / EOS-4.19.10M / EOS-4.18.9M / EOS-4.17.10M or later';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
