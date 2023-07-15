#TRUSTED 252c1ed52e7735177cb924351a30410a38192a623b31f3e142091f4b72921579f4fc7206baeb21010fd24ceb06e3bdaf2548ef3e56934f552452d0f9b82a35c7660fa4b3c837d77b359cb75d0cb919b0a86a09ecc7fa09485af56bfc90159f5ec7d3f70f40562e21d15efa89773fbd22cee3025364af8c0b3d48c2939104e61812a75440192dc0af090b635ff6c994fd8eb900be1e26fed78e8a4d801feba1133c0f4aadb53aa6991f251de103ab66c75a394e50b33ad3f8ba91d606ac4c8736b1696787f3d43d9dac46de06fc8e595c7321e770060260eef22af9b7e78de423fca1151a56da30c8dcd9532e9a6acb2bac381b2c1a7c1b392406499b60ed93e874fc4f7040aabb683577821311a8dab52faa0e0f94869c5ef4f59337f66a1359288004c166e49027ae89c16033dcc40fae25fc323235165920b0c961c3dbbad8d8457d7fd73e0215732c2c45078ba59617e2699040e60c3ea2d26afc34ef5bd7dc9f07255bab1e904b069cf76ec02a06bb79f57124d29236e8eb66d00da97d21887d24c124964818e2c3d9fe0f52b48f5030a5dbee87f43b2f4c5b3c75134d8d45e01c483500998e46d3742d2f01957d1046c40c4d7e604652e38054afec05f7c93439604f5dfd05d54a1a8720ea01a8258082f4fe301538ef9516e1f6d53306203577791b6e0e9a2143cfc9b4909cd785e4b4eb08f44cf9beb1f44ff4002f7b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107061);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id(
    "CVE-2015-8138",
    "CVE-2016-1547",
    "CVE-2016-1548",
    "CVE-2016-1549",
    "CVE-2016-1550"
  );
  script_bugtraq_id(
    81811,
    88200,
    88261,
    88264,
    88276
  );
  script_xref(name:"CERT", value:"718152");

  script_name(english:"Arista Networks EOS Multiple Vulnerabilities (SA0019)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities :

  - A flaw exists in NTP in the receive() function within
    file ntpd/ntp_proto.c that allows packets with an origin
    timestamp of zero to bypass security checks. An
    unauthenticated, remote attacker can exploit this to
    spoof arbitrary content. (CVE-2015-8138)

  - A flaw exists in NTP when handling crafted Crypto NAK
    Packets having spoofed source addresses that match an
    existing associated peer. A unauthenticated, remote
    attacker can exploit this to demobilize a client
    association, resulting in a denial of service condition.
    (CVE-2016-1547)

  - A flaw exists in NTP when handling packets that have
    been spoofed to appear to be coming from a valid ntpd
    server, which may cause a switch to interleaved
    symmetric mode. An unauthenticated, remote attacker can
    exploit this, via a packet having a spoofed timestamp,
    to cause the client to reject future legitimate server
    responses, resulting in a denial of service condition.
    (CVE-2016-1548)

  - A flaw exits in NTP when handling a saturation of
    ephemeral associations. An authenticated, remote
    attacker can exploit this to defeat the clock selection
    algorithm and thereby modify a victim's clock.
    (CVE-2016-1549)

  - A flaw exists in NTP in the message authentication
    functionality of libntp that is triggered when handling
    a series of specially crafted messages. An
    unauthenticated, remote attacker can exploit this to
    partially recover the message digest key.
    (CVE-2016-1550)");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1332-security-advisory-19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabe6203");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/17");
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
vmatrix["all"] =  make_list("0.0<=4.12.99");
vmatrix["F"] =    make_list("4.13.1.1<=4.13.6",
                            "4.14.0<=4.14.5",
                            "4.15.0<=4.15.4.1");

vmatrix["M"] =    make_list("4.13.5<=4.13.15",
                            "4.14.6<=4.14.12",
                            "4.15.5","4.15.6");

vmatrix["misc"] = make_list("4.14.5FX",
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
                            "4.15.1FX-7060QX",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4FX-7500E3",
                            "4.15.5FX-7500R");

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
