#TRUSTED 183ced7d76f6862badc87a6b0741e14f92130c333c678a060e64eb64871ed4ac1799a430e7a445991d0aa8830c24a77f79ea131de54bdae72721d1b53d07697d72e0874b885e22ebd0597639b23103fa44d416197169e8e04ef7848bac84eec93ab32d0eadbc1fc5970e502a75962f2a33ddbe441f1e97a7c5bc6e61fd94859884e1ae3b82df93f427207431ac2a5af334b66171a768447f4b822a7634199132663046306661291f9e5f64766d97c58e909cf00a3bbf3e4b4256ac7c108c6ad57aed3990e2f7d78f56d6c2c375407b313fba64af0445ef226a3092810b135e5679b2784b1db4ddd5160ff1a81d06a4e1fe2eb1f9c92a84ffc6d7d12913df638b23077ad06156a10a1a784dc64e0eaf1e2993a577a9e408d79e5a6e1c5cdc9822cb36cf1b2f38ee3789f520e4d7d25ac0fcb938957a09594bbf7778dd76834370dec19bcbe60d435d9136cf98c1fcaa562f6f54da45e2845e80f7597d8aaf8418355ab86f8946bb32a9efc5e3e54a3d3bf6df3f09516e436902649f370bb28d88cbb94b7eac2ffeb261fca68953fee8ed35ec1ca420d1f3604830e1c9124717d958ad74039f8e85ba950dac676dcf231fc49713a1bd8f4be2d95000fcd05345e536e71ccc74fb1a93b8bd701ef4e9e09a161d97d287ca4c03dd1d2da51c672aca886d6ffa0cb5f642a23257e77bb507a83180e81fff349bd7fad4a72b44b3cefe
###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11779);
  script_version ("1.26");
  script_cvs_date("Date: 2018/10/10 14:50:53");

  script_name(english:"FTP Server Copyrighted Material Present");
  script_summary(english:"Checks if the remote ftp server hosts mp3/wav/asf/mpg files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is hosting potentially copyright infringing
files.");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote FTP server is hosting mp3, wav,
avi, or asf files, which could be potentially copyright infringing.");
  script_set_attribute(attribute:"solution", value:
"Remove the files that are not in alignment with your organization's
security and acceptable use policies.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Copyright_infringement");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/26");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl", "ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

#
# The script code starts here :
#
include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default:21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

function get_files(socket, basedir, level)
{
  local_var r,p,s,l,k,sl,m;

  send(socket:socket, data:'CWD ' + basedir + '\r\n');
  r = ftp_recv_line(socket:socket);
  if(!egrep(pattern:"^250 ", string:r))return NULL;

  if( level > 3 )
    return NULL;

  p = ftp_pasv(socket:socket);
  if(!p)return NULL;

  s = open_sock_tcp(p, transport:get_port_transport(port));
  if(!s)return NULL;
  send(socket:socket, data:'NLST .\r\n' );
  r = ftp_recv_line(socket:socket);
  if ( egrep(string:r, pattern:"^150 ") )
  {
    l = ftp_recv_listing(socket:s);
    r = ftp_recv_line(socket:socket);
  }
  close(s);
  l = split(l, keep:0);
  m = make_list();
  foreach k (l)
  {
    m = make_list(m, basedir + k);
  }

  foreach k (l)
  {
    sl = get_files(socket:socket, basedir:basedir + k + '/', level:level + 1);
    if( !isnull(sl) )
    m = make_list(m, sl);
  }
  return m;
}

if(!login)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  login = "anonymous";
  pass  = "nessus@nessus.org";
}

report = NULL;
soc = ftp_open_and_authenticate( user:login, pass:pass, port:port );
if( soc )
{
  files = get_files(socket:soc, basedir:"/", level:0);
  num_suspects = 0;
  foreach file (files)
  {
    if(preg(pattern:".*\.(mp3|mpg|mpeg|ogg|avi|wav|asf|vob|wma|torrent)", string:file, icase:TRUE))
    {
      report += ' - ' + file + '\n';
      num_suspects ++;
      if( num_suspects > 40 )
      {
        report += ' - ... (more) ...\n';
        break;
      }
    }
  }
  close(soc);
}

if( report != NULL )
{
  report = '
Here is a list of files which have been found on the remote FTP
server. Some of these files may contain copyrighted materials, such as
commercial movies or music files.

If any of these files contain copyrighted material, and if they are
freely swapped among users, your organization might be held liable
for copyright infringement by associations such as the RIAA or MPAA.
' + report;

  security_note(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
