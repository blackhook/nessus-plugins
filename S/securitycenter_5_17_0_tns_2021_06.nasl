#TRUSTED 7f1861a40e7adb547ac97496a831afbd0b7385f5c3240ce366b1ccc4293d12c5de3a843f88c78aae13cf81f56f1528ad1dbdb95cc3a3d3da15c8cbb45102cf75ee34d6620bef8ea3dd0aa30a805b039776fae56a637efe1365a0d22dc8a190af3052e58d1c5e559a53854cf6fdb25849e26c2a4f75f1d73a08e500262e81535789d53fe5f1d846cf6c950117328eea5c80d571fdfcbf2eda3624b2b45d6f42a291d36827eafd56c26386b971234808a07a3bb7a99e85cecea9cb6d7dc43732fbf1cfd97b0b08b2ae09f08d05e1d2a3dd4bc210c3b80c9e1a71d27bf79c3a6b36acb170b06f367caab5cd19195443ade7a1ec53faadbdedbbd54c38b715a10d74b264decf79b91d40e76b3519557bbcbe83eb9f6695b57c7381f9c5e1c2d7ae016c2d79ba2c8bc1d8ddc51bda9feb52425edaec972bdf048e0613b4687ede21be5e6bf8875d11e3fa56d1ac72b35853daf9a4ba96c73618a48f868896f62c19faa3768669fd835fb13db585820fda0556015f0e733639faf46c3b5dbe72e08a12f62943ead3386ebc0696286b7718e3d1f41279e3c6f8239ce2f159cc7c9dfef85697f1cd78e07ceccda74ff08aa90e1ed7ccbe61faebede7c405e178f2861d5a91060950ced8585a6bc60c646e2cf6d1aa50b4084a9c84970c344748cfb685fbcb342cdfd781f7a6e7bad8d111fb03c2d676b64e49d53b7c235d008620dccf38
#TRUST-RSA-SHA256 5f90be284924f0bb259aa0c922aeb44145c57d23f257048980a9365c27813a0c38a83d5f1524afc9d8d4ffad0f1cc9960fe942ca6620251881701b4dffd75db4e578a2868a80eaad7ffec537235a9fa86d5e6e9439753b23418fc6adce7167af66e808df27f0fb1da98b5359ed3d34ceeda6e5b3cc85515c0e8db6aafd3e37c774744735f87ff365b948657df05a22b4eb2d855547fa313da83ee917103a14358e230508d79319f176e5cecb70662c36a425b00d62db76dfb4bde94bdb0e16942cea8055fe36ca562219c3b84c4c1f41fef68c97b10397ac5355855d6926b726c212e6d0fd5463abc3f51c454d98b4264281e1e8cf98cb68dc90def7deaec4f3dfc88343628c1a5def86d0d151271ed7226d2b07142f1f51941b730181442e47504effd0f26225bc60c55393ef024bf5beee9d79269d060221deded2ad4843ff1f7be822ad8069a3e048ab4be8f06d1f879946185ec9ea1a50945be7b2c16450729bfbcf91b58376e8c526ce8fc7e136710fe0fc5bfb73cd83164c534809ba3240eb44e9f136b8810257c5a53f792d2988123d16a442b2ad5e80a4982919cb4c207f80207c784618befdf247f80b92bc671bbc44a1fa3f926343156ce826de4a3d09cedcf133529bdc2d44a9b31419b1835129f7968015fa8d926c818bcacd01c8f939b33ed47d2b6fb03048a991c942de09e614b992781e5e56e89a48588a8e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148404);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-3449");
  script_xref(name:"IAVA", value:"2021-A-0149-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable.sc 5.16.0 / 5.17.0 OpenSSL DoS (TNS-2021-06)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable.sc application installed on the remote host is version 5.16.0 or
5.17.0 and affected by the following OpenSSL denial of service vulnerability:

  - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a
    TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial
    ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result,
    leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation
    enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1
    versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not
    impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-06");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2021041.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c531f5e9");
  script_set_attribute(attribute:"solution", value:
"Install Tenable.sc Patch SC-202104.1 or update to version 5.18.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

if (app_info.version !~ "^5.1[67].0$")
  audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version);

var patches = make_list('SC-202104.1');
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

vcf::report_results(app_info:app_info, fix:'Tenable.sc Patch SC-202104.1', severity:SECURITY_WARNING);

