#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150074);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"ArubaOS-CX < 10.3.0001 (ARUBA-PSA-2020-010)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS-CX installed on the remote host is prior to version 10.3.0001. It is, therefore, affected by
multiple vulnerabilities, as follows:

  - Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow
    in the Linux kernel when handling TCP Selective Acknowledgments (SACKs). A remote attacker could use this
    to cause a denial of service. (CVE-2019-11477)

  - Jonathan Looney discovered that the TCP retransmission queue implementation in tcp_fragment in the Linux
    kernel could be fragmented when handling certain TCP Selective Acknowledgment (SACK) sequences. A remote
    attacker could use this to cause a denial of service. (CVE-2019-11478)

  - Jonathan Looney discovered that the Linux kernel default MSS is hard-coded to 48 bytes. This allows a
    remote peer to fragment TCP resend queues significantly more than if a larger MSS were enforced. A
    remote attacker could use this to cause a denial of service. (CVE-2019-11479)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-010.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ArubaOS-CX version 10.3.0001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:arubanetworks:arubaos-cx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS-CX');

var constraints = [
  {'max_version' : '10.2.0060', 'fixed_display' : '10.3.0001' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
