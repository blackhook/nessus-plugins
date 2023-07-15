#TRUSTED a34516ad6c0e4c9c3f16c9ecb8b1ce060a84fd3590d82397ac65804f1334049648d52b04095aea1247ab263e07e64154ccb0e66fb109f78d43c8b915ade54ed473a875d6dd89ff697833d2b4d2474d7555f462618627668a75ed57c4034da1642173d74385b9743fe68dc5e97ea9b998445ee7a2e8c231694120a17d459fec6721c220d82a67f1128ea564718cecf64ed2c15fe4422b77b7fb4a98d1a789fd07685ce5d6020b3ca69e7a2b790e44c60a6ba0cb737f863047912cef7241cd1432c5950a309b40391b292f4d9a124d13f263675f6335b52f7bc0c438ef1006cc737186b65636a6ff0ae2ae1503e7a7c11f992e86a7f2a98bf7cbc017d18253dec37368076f62ebfd6d32be1138bcd39660c2ea76c789b796c30bc377fbaec74eb4ac00f7caa9443742e7700e881ca80015e254b6458984ab2c23faeb8972a7c9d39e5250444eb64c9dcc7819b9e47d68cd38f2b44dd78aaf0b200345bcd99d86e138e3051fe318e1ec285039dc66a8ac4badeee8046e97177cf5a3f73f6878ad1261f8d9833eb8216110ba6e4c58ec16f96f9d15be6e726fa74806d9c39baf923625051e57575ef75306445dc0cb1c138b6c89bb9379eba42417d2d5131502f36f0e714bb3ceb20492cb0c23647bc7d509ef9f5fc16ad8f9a863be571edbf9ab883e97992c20b06aa536947d257a3c4944349dd1929a4aba473087e94d0b9c6eb4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107062);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2016-2108");
  script_bugtraq_id(89752);

  script_name(english:"Arista Networks EOS ASN.1 Encoder RCE (SA0020)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by a remote code execution vulnerability in the ASN.1 encoder
due to an underflow condition that occurs when attempting to encode
the value zero represented as a negative integer. An unauthenticated,
remote attacker can exploit this to corrupt memory, resulting in the
execution of arbitrary code.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1334-security-advisory-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdf5a8ee");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version, or apply the patch file
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2108");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/20");
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
ext = "1.0.0e.Ar/3187103.CVE20162108hotfix";
sha = "bb4f22f54d244d2711b56dcf16ae710750da8060e1a94297d875daea0228cfb597253057b625a2e848f90bd5bf5d8ec2e89a75d4f3177d900729ae0d15bba0a2";
if(eos_extension_installed(ext:ext, sha:sha)) exit(0, "The Arista device is not vulnerable, as a relevant hotfix has been installed.");

vmatrix = make_array();
vmatrix["F"] =    make_list("4.15.0<=4.15.4.1");
vmatrix["M"] =    make_list("4.15.5M");
vmatrix["misc"] = make_list("4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1FXB.1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7060QX",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4FX-7500E3",
                            "4.15.5FX-7500R",
                            "4.15.5FX-7500R-bgpscale"
                            );

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
