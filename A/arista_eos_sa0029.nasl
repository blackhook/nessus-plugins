#TRUSTED 487c0b63bed4f0142b91023faacd256e053abb0cac8a6da652bc06a54f2cd98d552b1ca4b91dc0ff05d435941a722fda19e7e5b7ede662c27da0e788b5aff3c316ce16a58343bce529207071bbaacb219630ecc49c441d21d6ec005d91fb57f234c0cb0df5d9d5dbb8aa305b4d2cc1814dad7b79a96d59439c9cdb55763278f5f180c42529b175125d585198ada5d1eb9816222ae823610d7696952c3c7f3e647312ce34cbeb3d271bfbdfdeee5f6076221ce3b416d1da7146959ff9b61323c8e9634ddc3f53eb030ef077ddb79b2ecb2c3da36c26005a5cafd2d30903a38eb8eed125842006f5c62d7aed0508c3577bfe429e3449fd39d570ea52494432d80ce6e2ebd151e9bc6fc9d534340ea9af1471263c8df047c2550d0752411c0499ae40c12a26ce779bfd04f5aa458502a3119fdd4a922521da54b6a4a360c6277450e63b932dd01fc8a6102b135d9a4d784e3450f3a035e51b4098c7f448071c1ec9b732bfd77dd8fe38e0b740dab2aa71531338bde36d576fe20a5c96bfb5252f423e451fb806c011c39f61ff9178e3e07ec952ba47eb0a154251acaf3de899159baa937c9a822f79b5381cc6bd4d97439a83d6f991bf9a8fadb4bfe200be9fdd3e49248596b100b8808ac849b3064094a527c14e5df6c1b859917e4abc7199dd2475c897e8acb845e715ecf722da7995ea28ae68343571edaca0ecead169db63fa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107069);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2017-8231");

  script_name(english:"Arista Networks EOS MPBGP Denial of Service (SA0029)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by a potential denial of service vulnerability as a result
of improper processing of malformed MPBGP updates.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/3328-security-advisory-0029
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea999555");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include("arista_eos_func.inc");

version = get_kb_item_or_exit("Host/Arista-EOS/Version");

vmatrix = make_array();
vmatrix["all"] =  make_list("0.0<=4.14.99");
vmatrix["F"] =    make_list("4.15.0<=4.15.4.1",
                            "4.17.0<=4.17.3");

vmatrix["M"] =    make_list("4.15.5<=4.15.11",
                            "4.16.6<=4.16.11",
                            "4.17.4","4.17.5");

vmatrix["misc"] = make_list("4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1FXB.1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7260QX",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4FX-7500E3",
                            "4.15.5FX-7500R",
                            "4.15.5FX-7500R-bgpscale",
                            "4.16.6FX-7500R",
                            "4.16.6FX-7500R.1",
                            "4.16.6FX-7500R-bgpscale",
                            "4.16.6FX-7512R",
                            "4.16.6FX-7060X",
                            "4.16.6FX-7050X2",
                            "4.16.6FX-7050X2.2",
                            "4.16.7FX-7500R",
                            "4.16.7FX-7500R-bgpscale",
                            "4.16.7FX-7060X",
                            "4.16.7FX-7060X.1",
                            "4.16.7M-L2EVPN",
                            "4.16.7FX-MLAGISSU-TWO-STEP",
                            "4.16.7FX-ECMP-FIX",
                            "4.16.8FX-7500R",
                            "4.16.8FX-7060X",
                            "4.16.8FX-MLAGISSU-TWO-STEP",
                            "4.16.9FX-7500R",
                            "4.16.9FX-7060X",
                            "4.16.9-FXB",
                            "4.16.10FX-7060X",
                            "4.17.1FX-VRRP6LL",
                            "4.17.1.1FX-MDP",
                            "4.17.2FX-OpenStack",
                            "4.17.3FX-7500R",
                            "4.17.3FX-7500R.1"
                            );

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
