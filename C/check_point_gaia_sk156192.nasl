#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134891);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478");
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Check Point Gaia Operating System Administrator password truncation (sk156192)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Gaia Operating System which is affected by multiple vulnerabilities involving
the Linux Kernel's handling of TCP networking.
  - It is possible to overflow the 16bit width of TCP_SKB_CB(skb)->tcp_gso_segs which could result in the system crashing
    resulting in a Denial of Service. (CVE-2019-11477)

  - It is possible to fragment the TCP retransmission queue in tcp_fragment in the Linux Kernel when handling specific
    TCP Selective Acknowledgement sequences. This could be abused by an atacker to cause a Denial of Service. (CVE-2019-11478)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk156192&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ba8a64f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch and fix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/model", "Host/Check_Point/hotfixes", "Settings/ParanoidReport");

  exit(0);
}

include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Gaia Operating System';
firmware_version  = get_kb_item('Host/Check_Point/version');
model = get_kb_item('Host/Check_Point/model');
hotfix = get_kb_item('Host/Check_Point/hotfixes');

hotfix_mapping = {'R80.10':'sk116380', 'R80.20':'sk137592', 'R80.30':'sk116380', 'R80.20_3.10':'sk146212',
'R80.30_3.10':'sk152652', 'R80.20SP':'sk155832', 'SMB':'sk153433'};

# check if firmware version in hotfix_mapping and if it is using the relevant hotfix
if (hotfix_mapping[firmware_version] == hotfix)
{
  audit(AUDIT_DEVICE_NOT_VULN, 'The remote device running ' + app_name + ', Firmware Version ' + firmware_version + ', Hotfix ' + hotfix);
}
else
{
  report =
    '\n  Installed firmware version    : ' + firmware_version +
    '\n  Model                         : ' + model +
    '\n  vulnerable firmware was installed.\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
