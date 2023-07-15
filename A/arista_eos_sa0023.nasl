#TRUSTED 1ef6c64187ac9588dc9827c42b9fb78364373006266f69b847d6298a75ee67ee1f66b3739a5a278d84f608adb125f04db52a5f754fc0dbc2a150f07239eae7ee0ca85faca32c4c37199a06a2f9bdcaa69f3932069ac968887f6aa2b6b60805a4cb4418d5d56a1a42b246681dae7384a5ac4bf5c88e3f56856af9f4d290035cfb4c5690145c25968ce81beb579c72aa5b2d5a200abd780b210fd5df15cbc2e69a09e8f406c6279a68df5bc1c71ad6411f46dd2a5ca15aeadf16b71e50dd2411fecaf5855ca2e8475c11c3ef9870bafdee488675703e07721f1149bb4888a64e0603754458310e7c1234715593136fd8d6d6b929b1f6ac7493b391939db1002cfa822440e96e3e06dde146f605e252120f721593b0be3d89900ce5883b915be0a8f76f56b7a76ce43786fe8fc5f4197d66483e84c32018ce906510c2e6db051501b493f1d7d8df5747edaae8b0e977e2656d679dab27efff31c1706b64ccc7698f0bcebf34c1339613950d56b984253f3d1a4ffd7e9d2355339200b8e81eebaeee56ff123607eb62b44383fa860f520a67aa4f9a423e264f64892db5ad31e7b2276447c8b4b2124e63a9a9109638b700785425cf76ef29182eb55b8ad2d892b4f2d5c34ba0270b3232d444380390363843a891e8b4794f7d88c46b7108aef70d19b0dcd32ed8a3e72dece9ed289eb21aaa321a4921141b3377b6e2c389cc387a3f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107065);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2016-5696");
  script_bugtraq_id(91704);

  script_name(english:"Arista Networks EOS tcp_input Challenge ACKs Shared Counter Disclosure (SA0023)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by a flaw in the Linux kernel implementation within file
net/ipv4/tcp_input.c due to a failure to properly determine the rate
of challenge ACK segments. An unauthenticated, remote attacker can
exploit this issue to access the shared counter, thereby making it
easier for the attacker to hijack TCP sessions via a blind in-window
attack.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1461-security-advisory-23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71caec59");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version. Alternatively, apply the
hotfix or recommended mitigations referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include("arista_eos_func.inc");

version = get_kb_item_or_exit("Host/Arista-EOS/Version");

ext = "2.7.0/3431682.erahneostrunkcve20165696hotfix.5";
sha = "d669cd3c2c98d6b59cd9e0e0588baa14f5064eaa9dbdcdacc9b5c52210737f13fcd5d09f064db85074cfd5f15dcdd0eddce0cf9fc8be46c310ea";
if(eos_extension_installed(ext:ext, sha:sha)) exit(0, "The Arista device is not vulnerable, as a relevant hotfix has been installed.");

vmatrix = make_array();
vmatrix["F"] =    make_list(  "4.14.0<=4.14.4.2", "4.15.0<=4.15.4.1");
vmatrix["M"] =    make_list(  "4.14.5<=4.14.15",
                              "4.15.5<=4.15.7",
                              "4.16.6",
                              "4.16.7"
                            );

vmatrix["misc"] = make_list(  "4.14.5FX",
                              "4.14.5FX",
                              "4.14.5FX.1",
                              "4.14.5FX.2",
                              "4.14.5FX.3",
                              "4.14.5FX.4",
                              "4.14.5.1F-SSU",
                              "4.15.0FX",
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
                              "4.16.6FX-7512R",
                              "4.16.6FX-7500R.1",
                              "4.16.6FX-7500R-bgpscale",
                              "4.16.6FX-7500R",
                              "4.16.6FX-7060X",
                              "4.16.6FX-7050X2",
                              "4.16.7M-L2EVPN",
                              "4.16.7FX-MLAGISSU-TWO-STEP",
                              "4.16.7FX-7500R",
                              "4.16.7FX-7060X"
                            );

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
