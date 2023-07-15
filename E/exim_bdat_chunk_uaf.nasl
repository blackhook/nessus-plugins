#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104815);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-16943");

  script_name(english:"Exim < 4.89.1 Use-After-Free BDAT Remote Code Execution");
  script_summary(english:"Checks the SMTP banner and for CHUNKING support");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a remote code execution
flaw.");
  script_set_attribute(attribute:"description", value:
"According to its banner and supported extensions, the remote installation of
Exim is affected by a code execution flaw.  The implementation of the BDAT SMTP
verb for sending large binary messages introduced in Exim 4.88 can incorrectly
free an in-use region of memory, leading to memory corruption and potentially
allowing an attacker to execute code.");
  script_set_attribute(attribute:"see_also", value:"https://lists.exim.org/lurker/message/20171125.034842.d1d75cac.en.html");
  script_set_attribute(attribute:"solution", value:
"Update to Exim 4.89.1 or later, or Exim 4.90-RC3 or later. If you cannot
upgrade, edit your Exim configuration and set 'chunking_advertise_hosts' to an
empty value as a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port, exit_on_fail:TRUE);
if (!banner)
  audit(AUDIT_NO_BANNER, port);

if ("Exim" >!< banner)
  audit(AUDIT_NOT_LISTEN, 'Exim', port);

matches = pregmatch(pattern:"^220.*Exim ([0-9\.]+)(_RC[0-9]+)?", string:banner);
if (isnull(matches))
  audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

version = matches[1];
rc = matches[2];

# 4.88 is the first vulnerable version. All of 4.88 is vulnerable.
# 4.89.1 is the first official patched version in 4.89 branch.
# 4.90 is not yet released, but Debian is shipping its Release Candidates.
# 4.90_RC3 is the first 4.90 RC with a patch.

# Unless they've got a 4.90 release candidate, they need to upgrade to 4.89.1.
fix = "4.89.1";

# Between 4.90 and 4.88 inclusive. RCs are ignored.
if (ver_compare(fix:"4.90", ver:version, strict:FALSE) <= 0 &&
    ver_compare(fix:"4.88", ver:version, strict:FALSE) >= 0)
{
  # 4.90 is a special case, because a fix was added to a 4.90 release candidate.
  if (version == "4.90")
  {
    if (isnull(rc) || rc =~ "RC([3-9]|[1-9][0-9])")
      audit(AUDIT_INST_VER_NOT_VULN, "Exim", version + rc);
    else
      fix = "4.90_RC3";
  }
  else if (ver_compare(fix:"4.89.1", ver:version, strict:FALSE) >= 0)
  {
    audit(AUDIT_INST_VER_NOT_VULN, "Exim", version + rc);
  }
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, "Exim", version + rc);
}

socket = smtp_open(port:port, exit_on_fail:TRUE);
# Ask for the supported extensions.
if (!get_kb_item("TEST_exim_bdat_chunk_uaf_do_not_open_socket"))
  send(socket:socket, data:'EHLO ' + this_host_name() + '\r\n');
lines = smtp_recv_line(socket:socket, code:250);
smtp_close(socket:socket);

# If the first line isn't a 250, the server might not support EHLO
if (lines !~ "^250[- ]")
  audit(AUDIT_RESP_BAD, port, "an SMTP EHLO command");

if (!pgrep(pattern:"^250[- ]CHUNKING", string:lines))
  exit(0, "The Exim server listening on port " + port + " does not support CHUNKING/BDAT.");

security_report_v4(
  port:port,
  severity:SECURITY_HOLE,
  extra:
    '\n  Banner            : ' + strip(banner) +
    '\n  Installed version : ' + version + rc +
    '\n  Fixed version     : ' + fix +
    '\n  The CHUNKING / BDAT extension was found to be enabled.'
);
