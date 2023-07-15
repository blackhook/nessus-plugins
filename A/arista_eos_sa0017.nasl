#TRUSTED 5c03b7cda25c6e50903ea18829757131c08b414448f381ee3fa9bf1389f936a1aa728d94fe5ab48283f4ca3c462f77e0929a6d7bfa4408aca5d4d0d80d615230527156c6d0630c4241c1bec0b20efe7ce5a6558d87049782cb2c51dc4702b416290d328a8b5132b6e7c0f32f6b564ba8a1366272600c0e35138817d8542b5e5c829c58d39176fa67b248701ac2f45ff0d2068e3ebaec4e57ba84ad80b9eac4e18fa480e12717d00a79efcf4cd5cbd57a6b8a6622b7356c804dd1e964bd7818e84cab854d4e33d9676bc08aa9cb23a895c23b8b646efdf91b187653718c46a918326f0cc4057b86c86f02b766c03bf9292e0dff81ce741764923760b61d8d1b3d3b8df402d72e8e35cfd35f9007b73cdc2c263bd50eda2f77d267d3714c2c7e60b1fd041ca4630840e6ca350540da0fb02b90528bb54cef55baef3ae27b64d26f5a127c405938ed5c41cafe230e1bdd2eaf804983c9d6b9cbaa8accf4cbdc94f776790b9ebb49e5caeb016f6dd23d7211c828d7f90d42ab0ed6f4bc0b58ef97d501c18ae411f2daea8aabe35d6be4a50622bdefa7849c1fa4267b8bed5babcc498e8eb5726bb7ef8586f93d89f64fec713fb0c7b6a5654b89daa92f063b830f1188baa547b53a0360f3f5e772c3405f5bc01ccdbb207c2cdca5c639e13525bc6bb4366676c0ef9b6281bac83ee5411ae4da842e7925106279d81835e661dd46f1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107059);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2015-7547");
  script_bugtraq_id(83265);
  script_xref(name:"CERT", value:"457759");
  script_xref(name:"EDB-ID", value:"39454");
  script_xref(name:"EDB-ID", value:"40339");

  script_name(english:"Arista Networks EOS libresolv Overflow RCE (SA0017)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple stack-based buffer overflow conditions in the GNU
libresolv library, specifically within the send_dg() and send_vc()
functions, when handling DNS responses that trigger a call to the
getaddrinfo() function with the AF_UNSPEC or AF_INET6 address family.
An unauthenticated, remote attacker can exploit these issues, via a
specially crafted DNS response, to cause a denial of service condition
or the execution of arbitrary code.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1255-security-advisory-17
  script_set_attribute( attribute:"see_also", value:"http://www.nessus.org/u?050a280a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.13.15M / 4.14.12M / 4.15.5M
or later. Alternatively, apply the patch or recommended mitigation
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7547");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/08");
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
ext1="2.6.0/2980299.gamiltonsecAdvisory0017Patch.63";
sha1="16948241511ccf7044a8e1eeef4e55d2181194296ea02e22f2bd6df69a3f25386bf2938f3086f67a148d84d62ede10fc530fbbbd27a58bb49d4c642ecc675690";
ext2="glibc-common.i686.rpm 2.13/4Ar";
sha2="ccdf8ad84ac1a7985d89b026a6a311533a0f028c4a80c9a8fafa9b1ac4386fe169adb15145faea2e8c8f8cc8e9152f42150c9bd7df63b4dbd4612641d9aabded";

if(eos_extension_installed(ext:ext1, sha:sha1) || eos_extension_installed(ext:ext2, sha:sha2)) 
  exit(0, "The Arista device is not vulnerable, as a relevant hotfix has been installed.");

vmatrix = make_array();
vmatrix["all"] =  make_list("0.0<=4.11.99");
vmatrix["F"] =    make_list("4.13.1.1<=4.13.6",
                            "4.14.0<=4.14.5",
                            "4.15.0<=4.15.4");

vmatrix["M"] =    make_list("4.13.7<=4.13.14",
                            "4.14.6<=4.14.11");

vmatrix["misc"] = make_list("4.12.5.2",
                            "4.12.6.1",
                            "4.12.7.1",
                            "4.12.8", 
                            "4.12.8.1", 
                            "4.12.9", 
                            "4.12.10",
                            "4.12.11",
                            "4.14.5FX",
                            "4.14.5FX.1",
                            "4.14.5FX.2",
                            "4.14.5FX.3",
                            "4.14.5FX.4",
                            "4.14.5.1F-SSU",
                            "4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1FXB1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7260QX",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4FX-7500E3");
vmatrix["fix"] = "Apply one of the vendor supplied patches or upgrade to EOS 4.15.5M /4.14.12M / 4.13.15M or later";

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
