#TRUSTED a53370ab260638ec90299228bb633bb0c5633e0e36a34d27e21d2425844058aa8dfa1ade0e194263b326950235458478c10b7b9c274315f3e84c6579da58dcada3f8a875bb0aa46545befdb46e8c6eb060f280a20ceefb4f01f370e78ae43ba48b2076ab08c96af1475ad965f64e2812b3b2e193b2fe5818d05507d06ecc792b5547329e1d68f5e75fecedc0262f6a7615fedda0483074d6dd41c4fe8bcfacc8d55b26e45d6e19d0c9d3221bd2d45955630d46dbd33cccd55267662844b2ebfe3cc9fdc4924366e561cc38c1f59d62246d1f744a8bbe2a3b392d9f0bed2b8b2b59b657972650b1f2160a5c06ad5e85f1a42470454ddd7e98170b768983b4fc5bf75078b1964371be040ef0e1eba17cdb4889cc279e6aa7d951a43d57de808ff82b41b068cc9bc9068adeed564ff7df4e292029ac02fb12191d5f5cfd8582ae0741a54772a2f5d25b15af499e61692853321ca26c75eb71b02234aa8206e5a0a2e649f58fb09c3b1341e549d0104a954ab2333c302ec6a788eabdaf144acdc74b7fbd773e5f6318354e38d37c897678724fc8f95acc7673baded73cb1c560d6f778682bc272a8b0b65a6397b6c377329f22bb4506d0b7f2eed7913b0697816f726ddcf53a130d29348c6c0c093191e1020dd125b15176003156bedaad5bdd235aafaccd936b58cc63d15e722f2dca8def57253d968276b3848d637b8be8dc45ed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107063);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2016-4450");
  script_bugtraq_id(90967);

  script_name(english:"Arista Networks EOS ngx_chain_to_iovec NULL Pointer Deference DoS (SA0021)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability in NGINX due to a NULL
pointer dereference flaw in the ngx_chain_to_iovec() function within
file os/unix/ngx_files.c when handling specially crafted requests. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request to write a client request body to a temporary file,
to crash a worker process.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1354-security-advisory-21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b364c9b9");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version, or apply the patch file
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/13");
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
ext = "1.6.2/3236644.idburleydevdasturias.11";
sha = "d7124b02ae8505436a94a0440b2c4192b801b30bd84ed1a9c3672c8c4891fadca18b6221237fb959436c5dd084e95bc97317606c41c6b173993becbc13c857e6";
if(eos_extension_installed(ext:ext, sha:sha)) exit(0, "The Arista device is not vulnerable, as a relevant hotfix has been installed.");

vmatrix = make_array();
vmatrix["all"] =  make_list("4.12");
vmatrix["F"] =    make_list("4.13.1.1<=4.13.6",
                            "4.14.0<=4.14.4.2",
                            "4.15.0<=4.15.4.1");
vmatrix["M"] =    make_list("4.13.7<=4.13.15",
                            "4.14.5<=4.14.11",
                            "4.15.5",
                            "4.15.6",
                            "4.16.6");

vmatrix["misc"] = make_list("4.14.5FX",
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
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
