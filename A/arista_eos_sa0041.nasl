#TRUSTED 43cc18a8ebe97a0edbda4614a50e1c4e1d71fe387cd738cb849caacb77d2b6fe71455bc6b8ff3a4fa85899e15a58b25f8c3d70f46ae4c82941b903aee576d30deac722c28d1822b6022c6779985190bba3c0185f8831c2e7aa4b2610d971c927d769722a9c8b8e9d5bbdc246e5fcf10fa8e019afd330484439ca1370c090153a6d1296c7b6b830f71d71bd28652da854a0b70876368f41e8893991536a2ebc7a1b6baea6d517ca8eaa705c69bab65c63556361970f7cf35c8411386514e7c2fd4d795b340cdc0c55a8ff3d52c3f21fa070dc291083dbe35493ce878ac1f90b43374748ff0924d07726922cc3c973c75b7e20bb28ee0d214a9da98aed573936da935be913e9b4a6a693da502cee48467fccf41dc64ea1d26ef04a0a55c956ae59c84d0a2e88d01226ff78dc17d59c46280f9ccc441f3cafd0d9640ffa40a6f353609b0e45d0263d5f79e6d156144794a3417eabea991b374330dd2bd989e449313078b0dcbc35dccbe13deba4f59386f029b3afab5155ab707490f244d81a77d55699dfdd1597c9223e7a607ba143fcd8cedfe35987fc5253c85c7abb779749aa4f8b35153eadc08ef43ca25e268e778465fc367c9749340df74fa7c5822fecc820cd5ad92c7ee5d7d742dca6f0621e289171e72fed95d5cf6d645853303292243003322f46f45b527c0caf903d16e30ea196c8d0f7b9107e9f03d4d4a7a3081b
#TRUST-RSA-SHA256 7e40482058bf5e6552c2ed47992e24b9bdfcf8586388d281ab410bc0d46fdac0169482b6440bfa29f13adccd9a2c14d42ff022a1deaca8215b821d54b14ebd5b2363aebb043bdf4aa71c2388929262c7b692678788b8087816be208ed8f740145e921c37548bb3c2dbfd3191ed4495cf2dbaf8cf23ecb74fef918d16b9e1bd4e89fcfb0831c7bd4cd41c2bb68132b09ac895600a4ca0141552897842393674563fc8779353803de113fc8f8901d2a443921d0bb10e5f31112591562e8773be856fb131e545334e8cf1fa1a4ca0d75fa068e772d8ac5f826e9364cb7a89dcd71c9bbe50bfe06ccca1fa88841ea049356a39c55fc4e79d3d8f515679bb1d62efe8349dbbfc685c7dadc14a1ec23d96341d2c6302835c51c7eb6fd90b28b268958da91dca5de2f5194fffc610f30e42a434f9e0f0fd867ec639d20c103fa40e1398a054e1c87f4d04b31c79fb77886289eeb995490e79c12756d75b6de6804b94a330d76022086e0ec0b1aef90069e2e8dbf3a3ed1ecec1b016a1b99d761c5c54a4f594d83f028fc0e134f61db541431e0890f44ae2422523af6182f651e373b727e08ef73dd0bf47b90bae0d36e04b5b619562026e6cc79289f62213e427fad350c7664607c605850c5de77daad4edb06afa9a09a19114bfe9ed33fa7a4417443e8d03135ea783bbadfd616de240af2fe3ca64db29246083012001e287e0c53761
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134303);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_bugtraq_id(108798, 108801, 108818);
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Arista Networks EOS Linux Kernel TCP Multiple DoS (SA0041)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by multiple denial of service (DoS) vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by the following denial of service (DoS)
vulnerabilities related to TCP networking in the Linux kernel, which can be exploited by a remote, unauthenticated
attacker:

  - SACK Panic. The TCP_SKB_CB(skb)->tcp_gso_segs value is subject to an integer overflow in the Linux
    kernel when handling TCP Selective Acknowledgments (SACKs). (CVE-2019-11477)

  - SACK Slowness.  The TCP retransmission queue implementation in tcp_fragment in the Linux kernel can be
    fragmented when handling certain TCP Selective Acknowledgment (SACK) sequences. (CVE-2019-11478)

  - The Linux kernel default MSS is hard-coded to 48 bytes. This allows a remote peer to fragment TCP resend
    queues significantly more than if a larger MSS were enforced. (CVE-2019-11479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/8066-security-advisory-41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0073e92b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.22.1F, 4.21.7M, 4.20.14M, 4.19.13M, 4.18.12M or later or 4.21.2.3F or
4.21.6.1.1F, or apply the patch from the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
ext='SecurityAdvisory0041Hotfix.rpm 1.0.2/eng';
sha='7f19af46d5e520364039e4e4870a6906b233908b7ddeac6bb613bb956f797b64ede92d146d3824764502e1434d0f5f1c84db7a6c7723ac784b1db18d2b75f21a';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'not vulnerable, as a relevant hotfix has been installed');

version = get_kb_item_or_exit('Host/Arista-EOS/Version');

vmatrix = make_array();
vmatrix['all'] = make_list('0.0<=4.17.99');
vmatrix['F']   =  make_list('4.22.0');
vmatrix['M']   =  make_list('4.21.0<=4.21.6',
                            '4.20.0<=4.20.13',
                            '4.19.0<=4.19.12',
                            '4.18.0<=4.18.11');

vmatrix['fix'] = '4.22.1F, 4.21.7M, 4.20.14M, 4.19.13M, 4.18.12M or later or 4.21.2.3F / 4.21.6.1.1F';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
