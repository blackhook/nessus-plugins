#TRUSTED 187c0d3dc190fa0b77922cf95addb4dfac1e67bb70abc997800281d62358d4751c8a5c6b71da5c96d0a268100e7e22f1cfa754b3dd603524158b0af1028b10cd1c083b8618e62b46e03dd57baa2e141e549d0d49bc86282377f47c77f11f879bf884e7ebd4860dfd0476ff3abe98cf51824b3e13287dbf1d69ab3e621e6757a177556e90aa34a825d2aece9a24cd83ae9acb2106d6774df474fca2a40825ca4dd84c2975d44c405f813ee6679c07ecde33b81f4546764bc753aea2c1e9b4e813e3d2a0822a08b3540fe7b199b03886a3745b31f08eae3861f0add384ea545c268d8ffa96a44535d2315864c65757b9b86d5182fe1709c95f7ff202a7fc2c22e0f5972b7418f868a925a7319fe6c5ed1ca76c9454572ac6ae01bdae5caf99a05b65d12b04cea22bd890dc1c703e4fac658caa2c360c7d099974a3144945257da9d24d73eba62b64459b61f0e8f8e45c4dc5848197e5933d81eced2f6aeeb75d53ecde13694eb657badd4f04190f77ea0c2c46b6b223a486832e77b6d15b9a3a969753b0557d8e6d786f803a98bc52bd0fb2c7375afefc042bb1fccf6dbf5a43cecffc5d53338871940e53dfbe2a5610e357f30950af174d52892d9670a70a2a98490fbe58b076d54187bccd34c0d664fd2cbe7bbac81aa65d3d05ab15622882036490c882eea11bef4173de737d46f57db19c2bb57c123c8658ce656c7bbaf635
#TRUST-RSA-SHA256 a8b18bb38c3c7d2bfb792bbfb62b1b577db29f07d56838a4325152fb6749a73953f94448eef9ba2f81a3255db12bbb89f8a01ec1fc0c75a06245d3798bb85106265fab803f3cf08b806b2f17d94d639c00b98c50c7d94348cabb6de0660163981c5b08328d3374a71c70c376d4ebca55b34879a4b571497352f92281be9f4e4ef278c67cc808907c5aef58b22a2d6c2d103305e210cfad307276e51873feaca0b360128584c9361932a04fb66d381af67936d6573c431e96f6b6eaf00b976ce4586cd0b8d73954611ae07b8edf45faa2abea3f596f71a950d9d039ff708bc4243f2c7e6f22d74ac9fe6cd3b255185b13d03444e3b54447a908535b2713fbf718a6c5c2adf61722070cca5df0edbd1d4071cfb139c260ff45f236005b7c11c6fe86a601cd364ff5269b55cdd62d20a7a07af6d33d37096ddcb603f663cb3fac0473e8a53a4cdd6596141799346cf16a11bbe2478a7ffb8b9030452ebc79ee27d06ffa69dc8dcd04973ab32683bc8789c05cb9d181be2801eb08aad10c5bacb6441c7fb7faac9f171caa6c6a07f50e7bfeb4cf9bc951b71e9f8a801359b6088f7a4529a954d243ae7fecc52563a87f6ff83d08295ea55536ab69b3d9526982784675e007069c98ca6dff7aa2689ce3489ccc277e6f5f8e55e452e5378af043cd5ac396989f924437a8bcd8d30fea14c3f75dd878441794aa3b5f1237b3c4311e19
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144982);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2020-8617");
  script_xref(name:"JSA", value:"JSA11091");

  script_name(english:"Juniper Junos OS DoS (JSA11091)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11091 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11091");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11091");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D105'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D230'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S10'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S12'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S4'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S12'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S8'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S7'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5', 'fixed_display':'19.3R2-S5, 19.3R3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S2', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S2', 'fixed_display':'20.2R1-S2, 20.2R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set\s+system\s+services\s+dns\s+dns-proxy.*"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
