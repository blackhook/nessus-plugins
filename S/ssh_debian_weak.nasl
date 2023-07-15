#TRUSTED 20d4f28abb555379ba7e9c6e248c879d0f3f743e6ad6748745b190e4347dbaefe59a972f8ccd97e7abe8fcd937a1877730de360e86656ef7ca2758dbdf38cf318be1daa21bfee26f0f8b7519acac0b35abb8a29cbab910a0ab1d5617816dd4233c56145a4e981e277572755b12aae0f41da958f8d1efcde44fc27434ef41a396f5f287dfb88b3ba44bd402f1fc4220c58bc7be9a54d95c0372f3598e679fe26b1c1d09a2e673097f2849eb4ba0b2dd87c102831b86179f7ca2e657faf344f8011fa61e1efb27aa9386f20cecabfb420b2e83934463e9157af2f0992b58e896d775ef681d3522161685ca3e74f811742c687f75b3b2451b23aa9e32d20e0a508c438a9bbf7dc4bb0cb6a40059030e7f2b7b481b728550b2e299863809ec21999de89d6457cbc646957300560121f4a7d78438d3170323473c93cebf50b6002df23df3e80b657efa67fd79686b8108700c484371c11bb73acf4f52a2b653dd488e52baa6a823876ab1d6c0862cfba292887f299d0626b7ebe512922c218edf80a560a15b8bcf4174545b538e3f5a5c3aa43d43fe9c1bcaf822a16841c56ee617a3054137c18e9577be7c54f48105909abd6fc2d073a1a0ad8f08e465ea4358fea82706fdf709c9b4e6da919755d5ca0a397f46ad905b7dee965d8df692d77ba024ea7250f4cacd99e6a90728cb57ee8281e99c767ca53bf0b8b4c9313ded40175c
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32314);
 script_version ("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15"); 

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);

 script_name(english:"Debian OpenSSH/OpenSSL Package Random Number Generator Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH host keys are weak." );
 script_set_attribute(attribute:"description", value:
"The remote SSH host key has been generated on a Debian 
or Ubuntu system which contains a bug in the random number
generator of its OpenSSL library.

The problem is due to a Debian packager removing nearly all
sources of entropy in the remote version of OpenSSL.

An attacker can easily obtain the private part of the remote
key and use this to set up decipher the remote session  or
set up a man in the middle attack." );
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host
to be guessable. In particuliar, all SSH, SSL and OpenVPN key
material should be re-generated." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?107f9bdc" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
 
 script_summary(english:"Checks for the remote SSH public key fingerprint");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");


SSH_RSA = 0;
SSH_DSS = 1;



function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file;
 local_var tmp_list;

 if (type == SSH_RSA)
   file = "blacklist_rsa.inc";
 else if (type == SSH_DSS)
   file = "blacklist_dss.inc";

 if ( ! file_stat(file) ) return NULL;

 fd = file_open(name:file, mode:"r");
 if (!fd) return NULL;

 main_index = file_read_dword(fd:fd);

 for (i=0; i<main_index; i++)
 {
  c = file_read(fp:fd, length:1);
  offset = file_read_dword(fd:fd);
  length = file_read_dword(fd:fd);

  if (c == first)
  {
   file_seek(fp:fd, offset:offset);
   sec_index = file_read_dword(fd:fd);

   for (j=0; j<sec_index; j++)
   {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == second)
    {
     file_seek(fp:fd, offset:offset);
     tmp_list = file_read(fp:fd, length:length);

     len = strlen(tmp_list);
     pos = 0;

     for (j=0; j<len; j+=10)
       list[pos++] = substr(tmp_list, j, j+9);

     break;
    }
   }

   break;
  }
 }

 file_close(fd);

 return list;
}

function is_vulnerable_fingerprint(type, fp)
{
 local_var list, i, len;

 list = find_hash_list(type:type, first:fp[0], second:fp[1]);
 if (isnull(list))
   return FALSE;

 len = max_index(list);
 
 for (i=0; i<len; i++)
   if (list[i] == fp)
     return TRUE;

 return FALSE;
}

ports = get_kb_list("Services/ssh");
if (isnull(ports)) ports = make_list(22);
else ports = make_list(ports);

foreach port (ports)
{
  fingerprint = get_kb_item("SSH/Fingerprint/ssh-rsa/"+port);
  if (fingerprint)
  {
    ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:substr(ssh_hex2raw(s:fingerprint), 6, 15));
    if (ret)
    {
      security_hole(port);
      exit(0);
    }
  }

  fingerprint = get_kb_item("SSH/Fingerprint/ssh-dss");
  if (fingerprint)
  {
    ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:substr(ssh_hex2raw(s:fingerprint), 6, 15));
    if (ret)
    {
      security_hole(port);
      exit(0);
    }
  }
}
