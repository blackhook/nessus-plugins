#TRUSTED 36067044d58990ba1895309f5b66181a28f67dfed72db259889a20d1f63dd51a4bf7e1ad52d088b5e10c3b153a892307e001a62f9d869f9cf9deda0cd9cbeb207cb55ad44c7798778b7873308e4d19490f42999c10feec387bfd0d346d36a3f155a1a976a2a20f10895962edb58989f6b821292f43cc159915f91b3eedf6bfee67c81d81eccea18a3b2ba5c01b5efc6252cf62cedf991819af996111f7950b3b9d0dbea83f05a17b82297ce254c5e6adc81d2806155f7a997ccdb051a49dd40b724f6740bfa56e7d63bd50e4f26ccedef6eb68cfe0fd4e953e3b0c7ba93f33add58d03738927d67965e45b10275bb8d68f9931ef354978601bded82baf1c5d67b71726e0e200e49870a150a768d407acf480bfb7444b5d18f816d67d879ae2efa0e4d9e8be7a9ea3c69c92618a77f23bf131552c0468be5d4dd3d4c14a2af4ca0cbcbfad06a7482c49949115fa8aa12cbf5a168183992e6d6b69a2cb1c1990f20031fe5c5918a59c8972c88431f7d959707e8b1a3f7802b2c7330cb09836c54637e770492820652dad0e531ca25b092c0e1a10dd2587a20ca23b16ebeceede5a2ed0927b9637fe62970bdd83fd760bdd6bed2b862f2872b090f9f8935fc1c52262aca0d1fe591f657867b7a2bd0d0b769ed05790cbbe763c295cb2325f3f9c29bf26e59aab4cb5ce38cffebb8a7aa91acd1436d69ce7f82d0329b75275615c4e
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(32321);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/16");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);

 script_name(english:"Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)");
 script_summary(english:"Checks for the remote SSL public key fingerprint");

 script_set_attribute(attribute:"synopsis", value:"The remote SSL certificate uses a weak key.");
 script_set_attribute(attribute:"description", value:
"The remote x509 certificate on the remote SSL server has been generated
on a Debian or Ubuntu system which contains a bug in the random number
generator of its OpenSSL library. 

The problem is due to a Debian packager removing nearly all sources of
entropy in the remote version of OpenSSL. 

An attacker can easily obtain the private part of the remote key and use
this to decipher the remote session or set up a man in the middle
attack.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?107f9bdc");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224");
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host to be
guessable.  In particuliar, all SSH, SSL and OpenVPN key material should
be re-generated.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0166");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2020 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("x509_func.inc");

RSA_1024 = 0;
RSA_2048 = 1;

function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;

 if (type == RSA_1024)
   file = "blacklist_ssl_rsa1024.inc";
 else if (type == RSA_2048)
   file = "blacklist_ssl_rsa2048.inc";

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

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

key = parse_der_cert(cert:cert);
if (isnull(key)) exit(1, "Failed to parse the certificate from the service listening on port "+port+".");

key = key['tbsCertificate'];
key = key['subjectPublicKeyInfo'];
if(!isnull(key) && !isnull(key[1]) && !isnull(key[1][0]))
{
  key = key[1];
  key = key[0];
}

if(isnull(key)) exit(1, "Failed to extract public key in the certificate from the service listening on port "+port+".");

bits = der_bit_length(key);
if (bits == 2048)
  type = RSA_2048;
else if(bits == 1024)
  type = RSA_1024;
else exit(1, "Unsupported public key length in the certificate from the service listening on port "+port+".");

while (strlen(key) > 0 && ord(key[0]) == 0)
  key = substr(key, 1, strlen(key)-1);

if (strlen(key) == 0) exit(1, "Failed to parse the key from the certificate from the service listening on port "+port+".");

mod = "Modulus=" + toupper(hexstr(key)) + '\n';

hex = substr(SHA1(mod), 0, 9);

ret = is_vulnerable_fingerprint(type:type, fp:hex);
if (ret) security_hole(port);
