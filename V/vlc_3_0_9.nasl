#
# (C) Tenable Network Security, Inc.
#

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136422);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id(
    "CVE-2019-19721",
    "CVE-2020-6071",
    "CVE-2020-6072",
    "CVE-2020-6073",
    "CVE-2020-6077",
    "CVE-2020-6078",
    "CVE-2020-6079"
  );
  script_xref(name:"IAVB", value:"2020-B-0025-S");

  script_name(english:"VLC < 3.0.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 3.0.9. It is, therefore, affected by 
multiple vulnerabilities:

  - An exploitable denial-of-service vulnerability exists in the resource record-parsing functionality of Videolabs 
    libmicrodns 0.1.0. When parsing compressed labels in mDNS messages, the compression pointer is followed without checking 
    for recursion, leading to a denial of service. An attacker can send an mDNS message to trigger this vulnerability 
    (CVE-2020-6071).     

  - An exploitable code execution vulnerability exists in the label-parsing functionality of Videolabs libmicrodns 0.1.0. 
    When parsing compressed labels in mDNS messages, the rr_decode function's return value is not checked, leading to a 
    double free that could be exploited to execute arbitrary code. An attacker can send an mDNS message to trigger this 
    vulnerability (CVE-2020-6072).

  - An exploitable denial-of-service vulnerability exists in the TXT record-parsing functionality of Videolabs libmicrodns 0.1.0. 
    When parsing the RDATA section in a TXT record in mDNS messages, multiple integer overflows can be triggered, leading to a denial 
    of service. An attacker can send an mDNS message to trigger this vulnerability (CVE-2020-6073).

  - An exploitable denial-of-service vulnerability exists in the message-parsing functionality of Videolabs libmicrodns 0.1.0. 
    When parsing mDNS messages, the implementation does not properly keep track of the available data in the message, possibly leading 
    to an out-of-bounds read that would result in a denial of service. An attacker can send an mDNS message to trigger this 
    vulnerability (CVE-2020-6077).

  - An exploitable denial-of-service vulnerability exists in the message-parsing functionality of Videolabs libmicrodns 0.1.0. 
    When parsing mDNS messages in mdns_recv, the return value of the mdns_read_header function is not checked, leading to an uninitialized 
    variable usage that eventually results in a null pointer dereference, leading to service crash. An attacker can send a series of 
    mDNS messages to trigger this vulnerability (CVE-2020-6078).

  - An exploitable denial-of-service vulnerability exists in the resource allocation handling of Videolabs libmicrodns 0.1.0. 
    When encountering errors while parsing mDNS messages, some allocated data is not freed, possibly leading to a denial-of-service 
    condition via resource exhaustion. An attacker can send one mDNS message repeatedly to trigger this vulnerability through decoding 
    of the domain name performed by rr_decode (CVE-2020-6079).");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sb-vlc309.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VLC media player', win_local:TRUE);

constraints = [{'fixed_version':'3.0.9'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
