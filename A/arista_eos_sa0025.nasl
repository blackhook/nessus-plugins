#TRUSTED 54c04b6fa5fedc9ac0f523b8cfd0105671365c1548ab6b97df1129216b7aedfcbcf7374f97847a1760eb7ff095133ac68daf61e585ca1a6e5e6502acc9e2eb1aad139618047dfe4ea46566c402507194f4a3ef2cc5b524ec0c172b08efaee75740fbfc1112ef118692e1e7ccbd226069796cf938700affe408b159f72dc586cf0c1864d30fa3f64f6e46d10087ffc238a99a4dfc02676e741c899e4c582528387bc2b070ca011f885b633992c040de9c4bd5cdf4b3961014112d33e1a0a5dd31680dcdae7fe09574e23fcd7301034ba3946148d7c63d42be1f14fe28d12fa404aeb53cf6280fa60877f2f9be4c667f00db44616608f28a643b97030840e6fd35ada82e73b065fed315599ee706172d44f16323dffb24c73b95c6018ed363b6fa9159d4224e912042247b1c0983a4c6f660e34c4d555a12f6b8382f7897f7e303f243edc6957ea76ce7f70ca3f5d203eb7fb5b51b6d0fc9bfe62f72b59ce70037584f27c1bac06bea2ed66073ffb60a1e2ea7fc0693eeac468f5135f4dea12aa199e1552fb387fa76c53234c3241f760a5a4bae2e37920d09b7bd1e63bc2e8bc3d15434c97c7f09e6aabe96954de19ac0e2173cef838498ad579332f32d8a2721e55052568aa56af8737ab60764d986ffa45e74c377e5c7be027ec22bdb22ab29b4989adc188275660db859389197731fc76262eebc2328d56c3dad3596520c02
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107068);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2016-6894");
  script_bugtraq_id(95267);

  script_name(english:"Arista Networks EOS Control Plane Packet Handling DoS (SA0025)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by a denial of service vulnerability due to an unspecified
flaw when handling certain packets sent to the control plane. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to cause the device to reboot.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1752-security-advisory-25
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1c1e1fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.15.8M / 4.16.7M / 4.17.0F or
later. Alternatively, apply the recommended patch referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6894");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Host/Arista-EOS/Model");

  exit(0);
}


include("arista_eos_func.inc");

version = get_kb_item_or_exit("Host/Arista-EOS/Version");
model = get_kb_item_or_exit("Host/Arista-EOS/Model");
# The extension rpm says SecurityAdvisory0023 but this is the hotfix for sa0025
ext = "2.7.0/3450908.idcaldwellSecurityAdvisory0023hotfix.2";
sha = "8e9031d81ebe85b01f854f005b222e0a87d969f21d58c85c351707161224dbacc855840f8c5b17289fcf0d2417f6350be67c9adf2f5fe2624a15fdeb522ec291";

if(model !~ "^DCS-7050[QST]") audit(AUDIT_DEVICE_NOT_VULN, "Arista Networks " + model);

if(eos_extension_installed(ext:ext, sha:sha)) exit(0, "The Arista device is not vulnerable, as a relevant hotfix has been installed.");

vmatrix = make_array();
vmatrix["all"] =  make_list("4.15.2<=4.15.7.99",
                            "4.16.0<=4.16.6.99");
vmatrix["fix"] =  "Install the vendor-supplied patch or upgrade to Arista EOS 4.15.8M / 4.16.7M / 4.17.0F or later.";

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
