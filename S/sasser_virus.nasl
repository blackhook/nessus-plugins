#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12219);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

 script_name(english: "Sasser Virus Detection");
 script_summary(english: "Sasser Virus Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a virus." );
 script_set_attribute(attribute:"description", value:
"The Sasser worm is infecting this host.  Specifically,
a backdoored command server may be listening on port 9995 or 9996
and an ftp server (used to load malicious code) is listening on port 
5554 or 1023.  There is every indication that the host is currently 
scanning and infecting other systems." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3245f88a");
 # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2004/ms04-011
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3863b7ef");
 script_set_attribute(attribute:"solution", value:
"Use an antivirus to clean the host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute: "cvss_score_source", value: "CVE-2003-0533");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 
 script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

 script_require_ports(5554);
 exit(0);
}

# start script

include("ftp_func.inc");
var login = "anonymous";
var pass  = "bin";

# there really is no telling how many Sasser variants there will be :<
var ports = make_list();
ports[0] =  5554;           
ports[1] =  1023;

foreach port ( ports )
{
 if ( get_port_state(port) )
   {
        var soc = open_sock_tcp(port);
        if (soc) 
        {
            if(ftp_authenticate(socket:soc, user:login, pass:pass)) security_report_v4(port:port, severity:SECURITY_HOLE);
	    close(soc);
        }
    }
}