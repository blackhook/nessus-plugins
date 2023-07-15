#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133605);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-5390", "CVE-2019-5391");
  script_xref(name:"TRA", value:"TRA-2019-42");

  script_name(english:"HPE Intelligent Management Center dbman Command 10018 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A database backup and restoration tool running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HPE Intelligent Management Center (iMC) dbman process running
on the remote host is affected by multiple vulnerabilities : 

  - A command injection vulnerability exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this, via a series of specially crafted
    requests, to execute arbitrary commands. (CVE-2019-5390)

  - A stack-based buffer overflow condition exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this, via a series of specially crafted
    requests, to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2019-5391)

Note that the HPE iMC running on the remote host is reportedly
affected by additional vulnerabilities; however, this plugin has
not tested for these.");
  # https://medium.com/tenable-techblog/inadequate-patch-in-hewlett-packard-enterprise-imc-7-3-e0703-6aba36351ca3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c43db212");
  script_set_attribute(attribute:"solution", value:
"Upgrade HPE iMC version to 7.3 E0705 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_imc_dbman_detect.nbin");
  script_require_ports("hpe_imc_dbman", 2810);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('dump.inc');

port = get_service(svc:'hpe_imc_dbman', default:2810, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Incomplete cmd 10018: 2-byte length instead of 4
req = '\x00\x00\x27\x22' +  # command 10018
    '\x00\x00';             # 2-byte length
send(socket: soc, data: req);
res = recv(socket: soc, length:256);
err = socket_get_error(soc);
close(soc);

if(isnull(res))
{
  # The patched dbman treats command 10018 as an encrypted command.
  # The first 4 bytes in the request is a 32-bit length field.
  # The patched dbman checks if the length field is greater than 100.
  # If so, it will close the connection.
  # Since we specified 10018 as the first 4 bytes in the request,
  # the patched dbman will return nothing and close the connection.
  if(err == ECONNRESET)
    audit(AUDIT_HOST_NOT, 'affected');

  audit(AUDIT_RESP_NOT, port, 'a dbman command');
}

# The vulnerable dbman treats command 10018 as an unencrypted
# command. It expects a 4-byte length field at position 4 in the
# request. Since we only specified a 2-byte length field in the
# request, dbman fails to read the 4-byte length field and returns
# an error response message like this:
#
#0x00:  00 00 00 01 00 00 00 3A 30 38 02 01 FF 04 33 44    .......:08....3D
#0x10:  62 6D 61 6E 20 64 65 61 6C 20 6D 73 67 20 65 72    bman deal msg er
#0x20:  72 6F 72 2C 20 70 6C 65 61 73 65 20 74 6F 20 73    ror, please to s
#0x30:  65 65 20 64 62 6D 61 6E 5F 64 65 62 75 67 2E 6C    ee dbman_debug.l
#0x40:  6F 67                                              og
#
if('dbman_debug.log' >< res)
{
  extra = 'Nessus was able to detect the vulnerabilities by sending a' +
    ' specially crafted dbman command to the remote host.';
  security_report_v4(port: port, severity: SECURITY_HOLE, extra: extra);
}
else
  audit(AUDIT_RESP_BAD, port, 'a dbman command. Response: \n' + hexdump(ddata:res));
