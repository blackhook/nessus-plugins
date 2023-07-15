#TRUSTED 917632aaf82fcc83c46fd1aaabdb3631e78d923e4ef9f580f330e607dc84db8d7a72e51362dfc89703f5663cda47710470b17bb67a8ca9764c9e541465e7d6334ccf910a32ae97c4237fb3996d2ca595435fae2d50c37a0170c355a9997983d6bcd41eddcd0a87ff18413bcff13aa4df7272b5ff4b071d47a14948db43ce4763ab337c9ec767e8ca1793e9517a1a28716ce891a0f0d6bb88a0a92b9ab13859d23d0c9dae47660b537278400a275f8a5c3dc4b556e7d29941ba2e092b84429784738c1ad1df8cf3987b90da0f8826536bc3174bb46bb5f1ed770b071e4a770359a0ddf6fa483bd6f589a1b2426fc775b1d6bd160609eed61ff821fa2529597ef6f8f21f4f889befa3f89bbba769781edf086edd36052050f31ee894cf22ffa552590ce4c761e13c28380cb75c2fdd6af9a3446bb3aff7fdc2d9a79df89e5dc84f1099d36f0a13c8c7fca5b341be25331071d7363a77235add35cd39a9b77bb718147e989904b13c336e587d0cd938ed0978a5ef89557e5e80b067a7fc3e8b97a52a4c1e92d47af0f59a38c888e428cee9424c0b95559e8e9b3891b53c87f80d071a1cdce4aded02acd829b78bcac8d435953fe8434496b0ef9b98f09fa569cd94c24219d0337c58f2ba53f29c5b7b72c88b22268c416361fa3a3bf6cbd235ae4034a8478de9a6b0ce6f4e9d2b1085a0f38f8f71644dd29881dbf1624ead862d49
###
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10090);
 script_bugtraq_id(2241);
 script_version ("1.50");
 script_cve_id("CVE-1999-0080",
 	 	"CVE-1999-0955"  # If vulnerable to the flaw above, it's 
				 # automatically vulnerable to this one
				 # too...
		 
		 );
 script_name(english:"WU-FTPD SITE EXEC Arbitrary Local Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of WU-FTPD that is affected by a
command execution vulnerability. It is possible to execute arbitrary
command son the remote host using the 'site exec' FTP problem." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/1995/Jul/0");
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD 2.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0080");

 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1993/03/01");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Attempts to write on the remote root dir");
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 1999-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

cmd = make_array(
'set',	'RE:PATH=[./:]|^path[ \t]+\\([./].*\\)|HOME=/|home[ \t]+/',
'/bin/id', 'RE:uid=[0-9]',
'/usr/bin/id', 'RE:uid=[0-9]'
);

port = get_service(svc: 'ftp', default: 21, exit_on_fail: 1);

soc = ftp_open_and_authenticate( user:login, pass:password, port:port );
if (!soc)
{
  exit(1, "Could not authenticate on FTP server on port "+port+".");
}

foreach c (keys(cmd))
{
  data = 'SITE exec /bin/sh -c '+c+'\n';
  send(socket:soc, data:data);
  reply = recv_line(socket:soc, length:1024);
  txt = extract_pattern_from_resp(string: reply, pattern: cmd[c]);
  if (txt)
  {
    #set_kb_item(name:"ftp/root_via_site_exec", value:TRUE);
    if (report_verbosity <= 0)
      security_hole(port);
    else
      security_hole(port: port, extra: 
'\nThe following command :\n' +
data +
'produced :\n', txt, '\n');
    break;
  }
}

ftp_close(socket: soc);
exit(0);

