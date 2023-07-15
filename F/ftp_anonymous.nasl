#TRUSTED 2c3990bbe52e58c8c7dfec8def1113e31cdfeb0add3ee56bb3b4dc6442ddc664eb5607b963ea2999e0b1c65c7b564e99815903b85267b9b81de939386aa922a18188be93a115a7319606c3d1f348f192548f78b112259ee9eccf990d918cdd5efbb25aedd26dca5148f0b0bf36bde67eeedc7ab88111342403ecadb0506046f4c80da52b88a532765432b406ce647b91ba1a7c648260927d2191d4e97fdbc2fc714fe8fd51bf089ebab965fb06850d29f5d5dc5e08349a13aad50e63494fa2dd6f058f01bd274ff679b2c9089919043d3ff6740ce53b0ceeef34c68c06d9f392b4bc88fbd2fc141c17508fd290fe7c1a75202ceebfac2e02c9ad703bfe146a46774eadecc6e98bfe1828d2b03be338f0f4b12cafdfceef9eabd5d4a6f2206d5d21b5f7dba3dd3fc6c8957b236d678551abca6c2a2b18bd345478c19a61a5b80b5d713175febdc5f82e78ee77b1ea60fa8c21811b8933870d24d4553cc7332e267a1c24739ac2d2450e1364254a540185264b50b3a1eaed3c7e30aff00cceb355458555e61a8d0c558d5b9e1e450f8861050f1f3fa89fa1bde55562e812b0ced5a7929e38a281240ce3090b818c52700894e8fdf5942f5263fa45ad68a40607f5c579927db69f4d493ac7e45697647e502c75bd16d4b0426ef56a2b33ad789966e0dfe393d8137d41552079fa7c34602d3eedcbc28073726877eda3216ecd5ebf
###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10079);
 script_version("1.59");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

 script_cve_id("CVE-1999-0497");
 script_bugtraq_id(83206);

 script_name(english:"Anonymous FTP Enabled");
 script_summary(english:"Checks if the remote ftp server accepts anonymous logins.");

 script_set_attribute(attribute:"synopsis", value:
"Anonymous logins are allowed on the remote FTP server.");
 script_set_attribute(attribute:"description", value:
"Nessus has detected that the FTP server running on the remote host
allows anonymous logins. Therefore, any remote user may connect and
authenticate to the server without providing a password or unique
credentials. This allows the user to access any files made available
by the FTP server.");
 script_set_attribute(attribute:"solution", value:
"Disable anonymous FTP if it is not required. Routinely check the FTP
server to ensure that sensitive content is not being made available.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0497");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable gives a Confidentiality impact of Partial since the issue could allow unwanted access to file system.");
 script_set_attribute(attribute:"vuln_publication_date", value:"1993/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 1999-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("logins.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default: 21, broken:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


anon_accts = make_list(
  'anonymous',
  'ftp'
);

pass = "nessus@nessus.org";

foreach acct (anon_accts)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    r = ftp_authenticate(socket:soc, user:acct, pass:pass, port:port);
    if (r)
    {
      port2 = ftp_pasv(socket:soc);
      if (port2)
      {
        soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
        if (soc2)
        {
          send(socket:soc, data:'LIST\r\n');
          listing = ftp_recv_listing(socket:soc2);
          close(soc2);
        }
      }

      if (strlen(listing))
      {
        report = 'The contents of the remote FTP root are :\n' + listing;
      }

      if (report) security_warning(port:port, extra: report);
      else security_warning(port);

      set_kb_item(name:"ftp/anonymous", value:TRUE);
      set_kb_item(name:"ftp/"+port+"/anonymous", value:TRUE);
      user_password = get_kb_item("ftp/password");
      if (!user_password)
      {
        if (! get_kb_item("ftp/login"))
          set_kb_item(name:"ftp/login", value:acct);
        set_kb_item(name:"ftp/password", value:pass);
      }
      close(soc);
      exit(0);
    }
    close(soc);
  }
}
