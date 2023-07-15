#TRUSTED 213b30588f9f67022de6954f5c08c9406b434e7708f4edad80e597d2654f267cc8e938fddffa0bacf8af2270c98e80cf117046d5e8d296795a8710e7aa23fea27c059438289cfadf8ee6367b753cbd5b2937851292c8e91118fcbec0be87ec021fdf1297c780220da395cae98ca01bad37d2dbe97a7fd01d1ff7efb02dcf592a77451a1f322b320638abe19cbea7a02b903798abccfb83d8ef76192f53f74d30c10726d398b9e654a1b524aae1c09e7a6851bd382ecec91b08f1b37cf27e21e81d8fed8d891ecec838f0c5381fce54a705eebf73ddb82a19fcfd9ed19a304596137564034e07a02de1a2922cb66dbd0870f407db920731a760e0a5d7a2335f8aa7ec041bac3799c40931ae46a5a84671b5dead51c3019dfe143ba6f16df796ca2aa1eda87bec3178c8ebe6d13090d6dc6decb1342f005fa186758adb78954710a501c6417da72ae4721f7042688dbf2c53141a6d5a43a788933efef993867021d676c06a294972973ef3f64c9187c5af034fdcd73b4d2a14158565c3fb020faccb9de23abca107af74228f34451244b0222bef69f036ff58b3bf000add17eb1d18844905b9fc02805de444675e953dd1c39675519e48ed96ab22a2352984550df31e6fa27e1c3a341820d1089184879c2b196b3d4e8e80d8064d9aed17909c392ddb17ecef512346bbc83701e1f510fa86d399fddca741b7ff7e83c59c2d95db
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107064);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/09");


  script_name(english:"Arista Networks EOS IPv6 Neighbor Discovery Packet DoS (SA0022)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability due to a flaw when
handling specially crafted IPv6 Neighbor Discovery packets from non
link-local sources. An unauthenticated, remote attacker can exploit
this, via specially crafted packets, to fill up the packet processing
queue, thereby causing legitimate IPv6 Neighbor Discovery packets to
be dropped.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1356-security-advisory-22
  script_set_attribute( attribute:"see_also", value:"http://www.nessus.org/u?0854f1db");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version. Alternatively, apply the
recommended mitigations referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include("arista_eos_func.inc");

version = get_kb_item_or_exit("Host/Arista-EOS/Version");

vmatrix = make_array();
vmatrix["all"] =  make_list("4.10.1<=4.12.99");
vmatrix["F"] =    make_list("4.13.1.1<=4.13.6",
                            "4.14.0<=4.14.4.2", 
                            "4.15.0<=4.15.6"
                            );

vmatrix["M"] =    make_list("4.13.7<=4.13.15",
                            "4.14.5<=4.14.15",
                            "4.15.5<=4.15.6",
                            "4.16.6"
                            );

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
