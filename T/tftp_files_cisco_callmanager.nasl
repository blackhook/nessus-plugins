#%NASL_MIN_LEVEL 70300
#
# This NASL script was written by Martin O'Neal of Corsaire (http://www.corsaire.com)
# 
# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
# 

# Changes by Tenable:
# - Revised plugin title, family change (8/22/09)

############## description ################

# declare description

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19507);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Cisco CallManager TFTP File Detection");

  script_set_attribute(attribute:"synopsis", value:
"A TFTP server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has a TFTP server installed that is serving one or 
more Cisco CallManager files. These files do not themselves include 
any sensitive information, but do identify the TFTP server as being 
part of a Cisco CallManager environment. The CCM TFTP server is an 
essential part of providing VOIP handset functionality, so should 
not be exposed to unnecessary scrutiny.");
  script_set_attribute(attribute:"solution", value:
"If it is not required, disable or uninstall the TFTP server. 
Otherwise restrict access to trusted sources only.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tftpd_backdoor.nasl");
  script_require_keys("Services/udp/tftp");
  script_exclude_keys("tftp/backdoor");

  exit(0);
}

############## declarations ################

port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);

############## script ################

include('tftp.inc');
include('dump.inc');

file_list = make_list('/MOH/SampleAudioSource.xml','RingList.xml','Annunciator.xml');

# step through files

foreach file_name (file_list)
{
  data = tftp_get(port:port,path:file_name);
  tftp_ms_backdoor(data: data, port: port, file: file_name);
  if (strlen(data) > 0)
  {
    security_warning(port:port,proto:"udp", extra: 'File content :\n'+hexdump(ddata: data));
    exit(0);
  }
}


