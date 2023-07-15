#TRUSTED 9854d4a035645598d6d4a2bf77d33726ad7be07f9a2506ff2dea1bc45491e6cf84fd69657834f672d1d627b73ddf07257c6c246cca0fc7ef43e14882225df2f71ff56a05ac823d1666132d3f1329fb6632897dea66e8a225e5d5e1220e4dd5a35caf6a7fed6fc33e941387d2bafcdebf16734bad3e40dcbc4b3e9c808e0851f34fded1f8c4dc17d18a8b36d7a5825254cc98578421b91ed7e40ab2a91e4f6ac018fb09043f6c2a141ba8dea2f5399404e7198e093b29ac304120c0abf0278d26e646faeca81cb2a65c040427ecf56bf284e75a913e1dbc3e2bbca524df97fff9c3684ecfd1c6fdc96523d54886e2d5dc178f0db81b091a26bf8c9aa48d67cefe365b896cda4af6681c8efb39d19185c5f6ccb4b1279564df8a4b29fb6886fb20d291cfa0d49eb9db0830fd25944f9a39763d4369c41ece17232a8b689d17f81f7d22bbbcacdd2cc9b7cab1f09b74da94afe8eb28e9388681910d3f63986d0bf9e87b7ae582fe1f8241a7b64000183c9679f2fada022d064b355048e5dc35694b2b6986b6acfe6d30045ce40c6d50589b4c833eadeb133273f736df82a3925fb7393b14e654ebd7cc03ef3c2e93c287b52ed9fcd6de55c2b380c0b4313f83a73c16c27af8a2a9208573ac63f088fa817f223421bd610267d483040f56062c2602df526d65e7ff6f840309175c177d15681ed60a5af11d07435ae1deb172dbe663
#TRUST-RSA-SHA256 6e23649d7b989a7a0bb196ddb259488b534f6939a0c906d997aa311fa89856f78f4c2ceaf85e024da2b5e77605f16182a6e7623afdb31df019d1a0279419e05a5f3cc24fc313ae9592a411fabf9a4c0e55d1f24a3ef7a6aa5c390652c307d3d1ab512b078624033877ae145dc7a7a0f1ffa89969a361c1d989f24ec71fd8e6e1632636fbcfb4932bde51b26b37baf441e89dc723aabaa7edf75a5ad881654c8bd66e406f7de212e42c9da9ae1dcf034422d4306ec55cdeff192cabffe2ee36a8edc06bd40f94aff3e90891d6996189f1c522d16b7745f70e230a5dc40cec9c1e3f6e584c0b3dcf2a9e4ca7728e8bf80ba58ff92b482286faee17c0dc56bb6f3fdb45dae0bb353918033c16e88edfe65757ce73360053992ca675865ed6cb4617e70c1bea0663172b91d150b5c8b6483040de1fab2550ad7adab4b8ba0618316a5d5c671a8e9ab7cfe07533a13b0fbf55535b5c66dbefa57f67ff82ccac8778cb9a57f4fe7365bdb942c2b08512c5190411649ac680f7736b1803d40d1d4d66ef6d2e42fe57e3688330cb97ce1a867bce21348395c3629ba910c050dd13b7878cbad66579db24229915ec99bc04b5c559c28be86a1b89fa4f4b6c659b7f5525bea6feb9d2f89d4ffa8173816a8ac314e23831b239a4996763db51ce95a9286bfce55c936f55e51b291edcc1d8b63de9daa8e46901d9a81080f9c773c26a1ca83c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134419);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Arista Networks EOS Multiple Vulnerabilities (SA0043)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by the following vulnerabilities:

  - HTTP/2 implementations are vulnerable to ping floods, potentially leading to a denial of service (DoS).
    An unauthenticated, remote attacker can exploit this, by sending continual pings to an HTTP/2 peer,
    causing the peer to build an internal queue of responses. Depending on how efficiently this data is
    queued, this can consume excess CPU, memory, or both. (CVE-2019-9512)

  - HTTP/2 implementations are vulnerable to a reset flood, potentially leading to a DoS. An unauthenticated, 
    remote attacker can open a number of streams and send an invalid request over each stream that should
    solicit a stream of RST_STREAM frames from the peer. Depending on how the peer queues the RST_STREAM
    frames, this can consume excess memory, CPU, or both. (CVE-2019-9514)

  - HTTP/2 implementations are vulnerable to a settings flood, potentially leading to a DoS. An
    unauthenticated, remote attacker can exploit this by sending a stream of SETTINGS frames to the peer.
    Since the RFC requires that the peer reply with one acknowledgement per SETTINGS frame, an empty SETTINGS
    frame is almost equivalent in behavior to a ping. Depending on how efficiently this data is queued, this
    can consume excess CPU, memory, or both. (CVE-2019-9515)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/8762-security-advisory-43
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5070013");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or or mitigation or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Settings/ParanoidReport");

  exit(0);
}


include('arista_eos_func.inc');
include('audit.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');

if (version =~ "([^0-9]|^)4\.22\.(0|0\.1|0\.2|1|2)F" ||
    version =~ "([^0-9]|^)4\.23\.(0|0\.1)F")
{
  ext='SecurityAdvisory0043Hotfix-4.22-4.23.rpm 1.0.0/eng';
  sha='ef84fb5e4eb2ffe9f1cf2904cb1b496fb115c444de21f4cf38858daa4a0cba35a6cad9677d01b8f1885df42ff15368c864998eb4afcc7625e39195e08f65c669';

  if(eos_extension_installed(ext:ext, sha:sha))
    audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');
}
else if (version =~ "([^0-9]|^)4\.20\.(11|11\.1|12|12\.1|13|13\.1|14)M" ||
         version =~ "([^0-9]|^)4\.21\.(7|7\.1|8)M")
{
  ext='SecurityAdvisory0043Hotfix-4.20-4.21.rpm 1.0.0/eng';
  sha='be17fce400045ee63c7d77cb756e47aebf460c878793b1984ed3c79f7c3be3ec189c986afdcbc3d1814170d2e1f5c594b3ac7d179ebe05eda05c4919d9789036';

  if(eos_extension_installed(ext:ext, sha:sha))
    audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');
}


vmatrix = make_array();
vmatrix['all'] =  make_list('4.22<=4.22.2',
                            '4.21<=4.21.7.1',
                            '4.20<=4.20.14',
                            '4.19<=4.19.13',
                            '4.18<=4.18.99',
                            '4.17<=4.17.99');
vmatrix['F'] = make_list('4.23.0F');

vmatrix['fix'] = '4.20 >= 4.20.15M / 4.21 >= 4.21.9M / 4.22 >= 4.22.3F / 4.23 >= 4.23.1F';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
