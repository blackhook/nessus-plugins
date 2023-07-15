#TRUSTED 351706fff380b488af2991f365b5bb8322b8bd9cd5b163ac490d31bce952945ab922d7aff2cdd240ebbbb09af845a1214d4295010c8bf9975ec091889f713b3346ee127c217d9b543ebcd2ac74d35de7bcc36f2a7032f61d608539c7998753e6ece774c0c8fb555284f9219489295ed028b62fe48835c25cdf233bf93d91de0afbfd9000d10bc8307291658133d839e78570923805718738cf87e785d7e4b26df3fa4e335b42ec39059c4bdaf3ad1b6d0dd166b982bd88a3f5c39945e33f822b69ca09e474012dda6df3d2036d8235e76749c8a54eabe1488aedb93f43b4bd45fbce8a58a61c2e6cd4cc32ada6013716ac2ff769dd7488e44802477c8854355e7f64620635bc1bfb8b166d56f20fce0c9130523046dd33199b915d43309066e659b92ada4f17a798934017cbad710d13da33771963703e103de2da56df37b5f861645c6b2e697cceefaf80e76828d0c059ab1152f6f75830cb04db0b9ed2490fa36a5e8325b04518b1d67271086700b808020ced0fca6a6987acf2c23b5f9f6b36d3a9d2060d89c801892cb8dfaa67b3e55c8153727715dc380eda89562400f76d78fa15ec7d1fceed8a2235fa4a49557cc144b571bdd6ec63a1dd39e225836219015c013cd29114ca2c7586db78b812404f540a08c4e470bc726014f331a3db445f5165a65d2a9daf6717388b4cef9f1c4c42174a242692bdf2ea69787ee97d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50543);
  script_version("1.90");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_name(english:"OS Identification : SSL Certificates");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on an SSL
certificate.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the operating system by examining a
hard-coded SSL certificate issued by the device manufacturer.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

ports = get_ssl_ports();
if (empty_or_null(ports)) exit(1, "The host does not appear to have any SSL-based services.");

i = 0;
name            = make_array();
dev_type        = make_array();
confidence      = make_array();
issuer_cn_pat   = make_array();
issuer_org_pat  = make_array();
issuer_ou_pat   = make_array();
subject_cn_pat  = make_array();
subject_org_pat = make_array();
subject_ou_pat  = make_array();

name[i]            = "Aerohive HiveOS";
issuer_cn_pat[i]   = "^HiveAP$";
issuer_org_pat[i]  = "^Aerohive$";
issuer_ou_pat[i]   = "^Default$";
subject_cn_pat[i]   = "^HiveAP$";
subject_org_pat[i] = "^Aerohive$";
subject_ou_pat[i]  = "^Default$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Aruba Clearpass Policy Manager";
issuer_cn_pat[i]   = "^clearpass";
issuer_org_pat[i]  = "^PolicyManager";
subject_cn_pat[i]   = "^clearpass";
subject_org_pat[i] = "^PolicyManager";
dev_type[i]        = "embedded";
i++;

name[i]            = "Avocent MergePoint Unity KVM switch";
issuer_cn_pat[i]   = "^Avocent MergePoint Unity$";
issuer_org_pat[i]  = "^(avocent|Avocent MergePoint Unity)$";
subject_cn_pat[i]  = "^Avocent MergePoint Unity$";
subject_org_pat[i] = "^(avocent|Avocent MergePoint Unity)$";
dev_type[i]        = "switch";
i++;

name[i]            = "Barracuda SSL VPN";
issuer_cn_pat[i]   = "^sslvpn\.barracuda\.com";
issuer_org_pat[i]  = "^Untrusted Certificate";
issuer_ou_pat[i]   = "^Untrusted Certificate";
subject_cn_pat[i]  = "^sslvpn\.barracuda\.com";
subject_org_pat[i] = "^Untrusted Certificate";
subject_ou_pat[i]  = "^Untrusted Certificate";
dev_type[i]        = "VPN";
i++;

name[i]            = "Blue Coat Appliance";
issuer_org_pat[i]  = "^Blue Coat SG[0-9]+ Series$";
subject_org_pat[i] = "^Blue Coat SG[0-9]+ Series$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Canon imageRUNNER Printer";
issuer_cn_pat[i]   = "^Canon (iR-ADV|iR Series)";
subject_cn_pat[i]  = "^Canon (iR-ADV|iR Series)";
dev_type[i]        = "printer";
i++;

name[i]            = 'CISCO IOS\nCisco IOS XE';
confidence[i]      = 75;
issuer_cn_pat[i]   = "^IOS-Self-Signed-Certificate-[0-9a-fA-F]+";
subject_cn_pat[i]  = "^IOS-Self-Signed-Certificate-[0-9a-fA-F]+";
dev_type[i]        = "router";
i++;

name[i]            = 'Cisco Intrusion Management System';
issuer_org_pat[i]  = "^Cisco Systems, Inc$";
issuer_ou_pat[i]   = "^Intrusion Management System$";
subject_org_pat[i] = "^Cisco Systems, Inc$";
subject_ou_pat[i]  = "^Intrusion Management System$";
dev_type[i]        = "firewall";
confidence[i]      = 75;
i++;

name[i]            = "Cisco IPS";
issuer_ou_pat[i]   = "^IPS-[0-9]+";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^IPS-[0-9]+";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
dev_type[i]        = "embedded";
i++;

name[i]            = "Cisco Application Networking Manager";
confidence[i]      = 60;
issuer_ou_pat[i]   = "^Unknown$";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^Unknown$";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
dev_type[i]        = "embedded";
i++;

name[i]            = "Cisco NX-OS";
issuer_cn_pat[i]   = "^www.cisco.com/go/1000v";
issuer_ou_pat[i]   = "^SAVBU";
issuer_org_pat[i]  = "^Cisco Sytems Inc";                   # nb: this is indeed "Sytems"
subject_cn_pat[i]  = "^www.cisco.com/go/1000v";
subject_ou_pat[i]  = "^SAVBU";
subject_org_pat[i] = "^Cisco Sytems Inc";                   # nb: this is indeed "Sytems"
dev_type[i]        = "switch";
i++;

name[i]            = "Cisco NX-OS";
issuer_cn_pat[i]   = "^nxos";
issuer_ou_pat[i]   = "^nsstg";
issuer_org_pat[i]  = "^Cisco Systems Inc\.";
subject_cn_pat[i]  = "^nxos";
subject_ou_pat[i]  = "^nsstg";
subject_org_pat[i] = "^Cisco Systems Inc\.";
dev_type[i]        = "switch";
i++;

name[i]            = "CISCO VPN Concentrator";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
issuer_ou_pat[i]   = "^VPN .+ Concentrator";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^VPN .+ Concentrator";
dev_type[i]        = "VPN";
i++;

name[i]            = "CISCO VPN Hardware Client";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
issuer_ou_pat[i]   = "^VPN .+ Hardware Client";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^VPN .+ Hardware Client";
dev_type[i]        = "VPN";
i++;

name[i]            = "Cisco IMC";
confidence[i]      = 75;
issuer_cn_pat[i]   = "^C-series CIMC";
#issuer_ou_pat[i]   = "PID:UCSC-C220-M4S SERIAL:FCH204576EH";
issuer_org_pat[i]  = "^Cisco";
subject_cn_pat[i]  = "^C-series CIMC";
#subject_ou_pat[i]  = "PID:UCSC-C220-M4S SERIAL:FCH204576EH";
subject_org_pat[i] = "^Cisco";
dev_type[i]        = "embedded";
i++;

name[i]            = "Citrix NetScaler";
issuer_cn_pat[i]   = "^default";
issuer_org_pat[i]  = "^Citrix ANG";
issuer_ou_pat[i]   = "^NS Internal";
subject_cn_pat[i]   = "^default";
subject_org_pat[i] = "^Citrix ANG";
subject_ou_pat[i]  = "^NS Internal";
dev_type[i]        = "embedded";
i++;

name[i]            = "Corero TopLayer IPS";
dev_type[i]        = "embedded";
issuer_cn_pat[i]   = "^Attack Mitigator IPS ";
issuer_org_pat[i]  = "^Corero Network Security, Inc\.";
issuer_ou_pat[i]   = "^support$";
subject_cn_pat[i]   = "^Attack Mitigator IPS ";
subject_org_pat[i] = "^Corero Network Security, Inc\.";
subject_ou_pat[i]  = "^support";
i++;

name[i]            = "HP 3PAR";
issuer_cn_pat[i]   = "^HP 3PAR HP_3PAR";
subject_cn_pat[i]  = "^HP 3PAR HP_3PAR";
dev_type[i]        = "embedded";
i++;

name[i]            = "HP JetDirect";
issuer_cn_pat[i]   = "^HP Jetdirect";
issuer_org_pat[i]  = "^Hewlett-Packard";
subject_cn_pat[i]  = "^HP Jetdirect";
subject_org_pat[i] = "^Hewlett-Packard";
dev_type[i]        = "printer";
i++;

name[i]            = "HP Access Point";
issuer_cn_pat[i]   = "^wireless\.hp\.local";
issuer_org_pat[i]  = "^Hewlett-Packard";
issuer_ou_pat[i]   = "^HP Networking";
subject_cn_pat[i]  = "^wireless\.hp\.local";
subject_org_pat[i] = "^Hewlett-Packard";
subject_ou_pat[i]  = "^HP Networking";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "Cyber Switching ePower PDU";
issuer_org_pat[i]  = "^Cyber Switching, Inc\.";
subject_org_pat[i] = "^Cyber Switching, Inc\.";
dev_type[i]        = "embedded";
i++;

# nb: there are 3 fingerprints for Dell DRAC / iDRAC
name[i]            = "Dell DRAC";
issuer_cn_pat[i]   = "^cmcdefault";
issuer_ou_pat[i]   = "^OpenCMC Group";
issuer_org_pat[i]  = "^Dell Inc\.";
subject_cn_pat[i]  = "^cmcdefault";
subject_ou_pat[i]  = "^OpenCMC Group";
subject_org_pat[i] = "^Dell Inc\.";
dev_type[i]        = "embedded";
i ++;

name[i]           = "Dell iDRAC";
issuer_cn_pat[i]   = "(iDRAC[67]|DRAC5|RAC) default certificate";
issuer_org_pat[i]  = "^Dell (Computer|Inc\.)";
subject_cn_pat[i]  = "(iDRAC[67]|DRAC5|RAC) default certificate";
subject_org_pat[i] = "^Dell (Computer|Inc\.)";
dev_type[i]        = "embedded";
i ++;

name[i]            = "Dell iDRAC 6";
issuer_cn_pat[i]   = "^iDRACdefault[0-9A-F]+$";
issuer_ou_pat[i]   = "^iDRAC Group$";
issuer_org_pat[i]  = "^Dell Inc\.$";
subject_cn_pat[i]  = "^iDRACdefault[0-9A-F]+$";
subject_ou_pat[i]  = "^iDRAC Group$";
subject_org_pat[i] = "^Dell Inc\.$";
dev_type[i]        = "embedded";
i ++;

name[i]            = "SonicWALL";
confidence[i]      = 70;
issuer_org_pat[i]  = "^HTTPS Management Certificate for SonicWALL \(self-signed\)";
subject_org_pat[i] = "^HTTPS Management Certificate for SonicWALL \(self-signed\)";
dev_type[i]        = "embedded";
i++;

name[i]            = "Buffalo TeraStation NAS";
issuer_cn_pat[i]   = "^develop";
issuer_org_pat[i]  = "^BUFFALO INC\.";
issuer_ou_pat[i]   = "^NAS";
subject_cn_pat[i]  = "^develop";
subject_org_pat[i] = "^buffalo";
subject_ou_pat[i] = "^NAS";
dev_type[i]        = "embedded";
i++;

name[i]            = "Technicolor / Thomson Wireless Router";
issuer_cn_pat[i]   = "^Thomson TG[0-9]+";
issuer_org_pat[i]  = "^THOMSON$";
subject_cn_pat[i]  = "^Thomson TG[0-9]+";
subject_org_pat[i] = "^THOMSON$";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "Colubris MAP-330 AP";
issuer_cn_pat[i]   = "^wireless\.colubris.com";
issuer_org_pat[i]  = "^Colubris Networks Inc\.$";
subject_cn_pat[i]  = "^wireless\.colubris\.com";
subject_org_pat[i] = "^Colubris Networks Inc\.$";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "VMware ESX";
issuer_org_pat[i]  = "^VMware(, Inc| Installer)";
subject_org_pat[i] = "^VMware, Inc";
subject_ou_pat[i]  = "^VMware ESX Server (Default )?Certificate";
dev_type[i]        = "hypervisor";
i++;

name[i]            = "Linux Kernel 2.6 on an EMC Celerra Network Server";
issuer_org_pat[i]  = "^Celerra Certificate Authority";
issuer_cn_pat[i]   = "^emcnas_";
subject_org_pat[i] = "^Celerra Control Station Administrator";
dev_type[i]        = "embedded";
i++;

name[i]            = "Polycom Teleconferencing Device";
issuer_org_pat[i]  = "^Polycom Inc\.$";
issuer_ou_pat[i]   = "^Video Division$";
subject_org_pat[i] = "^Polycom Inc\.$";
subject_ou_pat[i]  = "^Video Division$";
dev_type[i]        = "embedded";
confidence[i]      = 75;
i++;

# Fingerprints for Oracle ILOM and Exadata.
# We need two for the former, and one for the latter.

name[i]            = "Oracle Integrated Lights Out Manager";
issuer_cn_pat[i]   = "^Oracle Integrated Lights Out Manager$";
issuer_org_pat[i]  = "^Oracle";
subject_cn_pat[i]  = "^Oracle Integrated Lights Out Manager$";
subject_org_pat[i] = "^Oracle";
dev_type[i]        = "embedded";
i++;

# Only Organization and Organization Unit seem available for these 2.

name[i]            = "Oracle Integrated Lights Out Manager";
issuer_org_pat[i]  = "^Oracle";
issuer_ou_pat[i]   = "^Oracle Integrated Lights Out Manager$";
subject_org_pat[i] = "^Oracle";
subject_ou_pat[i]  = "^Oracle Integrated Lights Out Manager";
dev_type[i]        = "embedded";
i++;

# Not sure on how to describe Exadata device type. embedded for now.

name[i]            = "Oracle Exadata" ;
issuer_org_pat[i]  = "^Oracle";
issuer_ou_pat[i]   = "^Oracle Exadata$";
subject_org_pat[i] = "^Oracle";
subject_ou_pat[i]  = "^Oracle Exadata$";
dev_type[i]        = "embedded";
i++;

name[i]            = "IBM Storwize";
issuer_cn_pat[i]   = "^2072$";
issuer_org_pat[i]  = "^IBM$";
subject_cn_pat[i]  = "^2072$";
subject_org_pat[i] = "^IBM$";
subject_ou_pat[i] = "^SSG$";
dev_type[i]        = "embedded";
confidence[i]      = 75;
i++;

name[i]            = "Isilon OneFS";
issuer_cn_pat[i]   = "^Isilon Systems";
issuer_org_pat[i]  = "^Isilon Systems, Inc\.$";
subject_cn_pat[i]  = "^Isilon Systems";
subject_org_pat[i] = "^Isilon Systems, Inc\.$";
dev_type[i]        = "embedded";
confidence[i]      = 75;
i++;

name[i]            = "Mandiant Intelligent Response appliance";
issuer_cn_pat[i]   = "^MIR_CA$";
issuer_org_pat[i]  = "^Mandiant$";
subject_org_pat[i] = "^Mandiant$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Mitel IP Communications Platform";
issuer_cn_pat[i]   = "^Mitel Networks ICP$";
issuer_ou_pat[i]   = "^VoIP Platforms$";
subject_cn_pat[i]  = "^Mitel Networks ICP CA$";
subject_ou_pat[i]  = "^VoIP Platforms$";
dev_type[i]        = "pbx";
i++;

name[i]            = "NETGEAR FVS318 ProSafe VPN Firewall";
issuer_org_pat[i]  = "^Netgear";
issuer_ou_pat[i]   = "^Certificate for FVS318 \(Self-Signed\)";
subject_org_pat[i] = "^Netgear";
subject_ou_pat[i]  = "^Certificate for FVS318 \(Self-Signed\)";
dev_type[i]        = "firewall";
i++;

name[i]            = "NETGEAR FVS318G ProSafe VPN Firewall";
issuer_org_pat[i]  = "^Netgear";
issuer_ou_pat[i]   = "^Certificate for FVS318G \(Self-Signed\)";
subject_org_pat[i] = "^Netgear";
subject_ou_pat[i]  = "^Certificate for FVS318G \(Self-Signed\)";
dev_type[i]        = "firewall";
i++;

name[i]            = "NETGEAR FVS318N ProSafe Wireless-N VPN Firewall";
issuer_org_pat[i]  = "^Netgear";
issuer_ou_pat[i]   = "^Certificate for FVS318N \(Self-Signed\)";
subject_org_pat[i] = "^Netgear";
subject_ou_pat[i]  = "^Certificate for FVS318N \(Self-Signed\)";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "Palo Alto Networks PAN-OS";
issuer_org_pat[i]  = "^Palo Alto Networks$";
issuer_ou_pat[i]   = "^Support$";
subject_org_pat[i] = "^Palo Alto Networks$";
subject_ou_pat[i]  = "^Support$";
dev_type[i]        = "firewall";
i++;

name[i]            = "PelcoLinux";
issuer_cn_pat[i]   = "^localhost$";
issuer_org_pat[i]  = "^Pelco$";
subject_cn_pat[i]  = "^localhost$";
subject_org_pat[i] = "^Pelco$";
dev_type[i]        = "embedded";
i++;

name[i]            = "HP Integrated Lights Out";
issuer_cn_pat[i]   = "^iLO Default Issuer";
issuer_org_pat[i]  = "^Hewlett-Packard Company";
subject_cn_pat[i]  = "^iLO Default Issuer";
subject_org_pat[i] = "^Hewlett-Packard Company";
dev_type[i]        = "embedded";
i++;

name[i]            = "HP Onboard Administrator";
issuer_org_pat[i]  = "^Hewlett-Packard$";
issuer_ou_pat[i]   = "^Onboard Administrator$";
subject_org_pat[i] = "^Hewlett-Packard$";
subject_ou_pat[i]  = "^Onboard Administrator$";
dev_type[i]        = "embedded";
i++;

name[i]            = "EMC CLARiiON";
issuer_org_pat[i]  = "^EMC$";
issuer_ou_pat[i]   = "^CLARiiON$";
subject_org_pat[i] = "^EMC$";
subject_ou_pat[i]  = "^CLARiiON$";
dev_type[i]        = "embedded";
confidence[i]      = 85;
i++;

name[i]            = "EMC Data Domain OS";
issuer_org_pat[i]  = "^Valued Datadomain Customer$";
issuer_ou_pat[i]   = "^Root CA$";
subject_org_pat[i] = "^Valued DataDomain customer$";
subject_ou_pat[i]  = "^Host Certificate";
dev_type[i]        = "embedded";
confidence[i]      = 85;
i++;

name[i]            = "Net Optics Director";
subject_cn_pat[i]  = "Director\.netoptics\.com";
issuer_org_pat[i]  = "^Net Optics, Inc\.$";
subject_org_pat[i] = "^Net Optics, Inc\.$";
dev_type[i]        = "switch";
i++;

name[i]            = "FortiOS on Fortinet FortiGate";
dev_type[i]        = "firewall";
issuer_cn_pat[i]   = "^support$";
issuer_org_pat[i]  = "^Fortinet$";
issuer_ou_pat[i]   = "^Certificate Authority$";
subject_org_pat[i] = "^Fortinet$";
subject_ou_pat[i]  = "^FortiGate$";
i++;

name[i]            = "Cisco Video Communication Server";
confidence[i]      = 65;
dev_type[i]        = "embedded";
issuer_cn_pat[i]   = "^TANDBERG$";
issuer_org_pat[i]  = "^TANDBERG ASA$";
issuer_ou_pat[i]   = "^R&D$";
subject_cn_pat[i]  = "^TANDBERG$";
subject_org_pat[i] = "^TANDBERG ASA$";
subject_ou_pat[i]  = "^R&D$";
i++;

name[i]            = "PCoIP Zero Client";
confidence[i]      = 80;
dev_type[i]        = "embedded";
issuer_cn_pat[i]   = "^PCoIP Root CA$";
issuer_ou_pat[i]   = "^PCoIP Root$";
subject_ou_pat[i]  = "^PCoIP Device$";
i++;

name[i]            = "Silver Peak Systems";
dev_type[i]        = "embedded";
issuer_org_pat[i]  = "^Silver Peak Systems Inc";
issuer_ou_pat[i]   = "^Networking Appliance";
subject_org_pat[i] = "^Silver Peak Systems Inc";
subject_ou_pat[i] = "^Networking Appliance";
i++;

name[i]            = "Juniper Junos Space";
dev_type[i]        = "embedded";
issuer_org_pat[i]  = "^Juniper Networks, Inc.$";
issuer_ou_pat[i]   = "^Junos Space$";
subject_org_pat[i] = "^Juniper Networks, Inc.$";
subject_ou_pat[i]  = "^Junos Space$";
i++;

name[i]            = "QNAP QTS on a TS-Series NAS";
issuer_cn_pat[i]   = "^TS Series NAS";
issuer_org_pat[i]  = "^QNAP Systems Inc\.";
issuer_ou_pat[i]   = "^NAS";
subject_cn_pat[i]  = "^TS Series NAS";
subject_org_pat[i] = "^QNAP Systems Inc\.";
subject_ou_pat[i] = "^NAS";
dev_type[i]        = "embedded";
i++;

name[i]            = "Lantronix SLC";
issuer_cn_pat[i]   = "^SLC$";
issuer_org_pat[i]  = "^Lantronix$";
subject_cn_pat[i]  = "^SLC$";
subject_org_pat[i] = "^Lantronix$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Siemens PLC";
issuer_cn_pat[i]   = "^Siemens Root CA$";
issuer_org_pat[i]  = "^Siemens$";
subject_cn_pat[i]  = "^jupps$";
subject_org_pat[i] = "^Siemens AGs$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Grandstream PBX";
issuer_cn_pat[i]   = "^Grandstream$";
issuer_org_pat[i]  = "^Grandstream Networks, Inc$";
subject_cn_pat[i]  = "^Grandstream$";
subject_org_pat[i] = "^Grandstream Networks, Inc$";
dev_type[i]        = "pbx";
i++;


name[i]            = "Barco WePresent";
issuer_cn_pat[i]   = "^barco.com$";
issuer_org_pat[i]  = "^Barco Limited$";
issuer_ou_pat[i]   = "^Application Engineering Team$";
subject_cn_pat[i]  = "^barco.com$";
subject_org_pat[i] = "^Barco Limited$";
subject_ou_pat[i]  = "^Application Engineering Team$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Extron ShareLink";
issuer_cn_pat[i]   = "^AWiND$";
issuer_org_pat[i]  = "^AWiND$";
issuer_ou_pat[i]   = "^Embedded$";
subject_cn_pat[i]  = "^AWiND$";
subject_org_pat[i] = "^AWiND$";
subject_ou_pat[i]  = "^Embedded$";
dev_type[i]        = "embedded";
i++;

name[i]            = "pfSense";
issuer_cn_pat[i]   = "^pfSense-";
issuer_org_pat[i]  = "^pfSense webConfigurator Self-Signed Certificate$";
subject_cn_pat[i]  = "^pfSense-";
subject_org_pat[i] = "^pfSense webConfigurator Self-Signed Certificate$";
dev_type[i]        = "firewall";
i++;

name[i]            = "Alcatel-Lucent Appliance";
confidence[i]      = 75;
issuer_cn_pat[i]   = "^webview$";
issuer_org_pat[i]  = "^Alcatel-Lucent$";
subject_cn_pat[i]  = "^webview$";
subject_org_pat[i] = "^Alcatel-Lucent$";
subject_ou_pat[i] = "^ESD$";
dev_type[i]        = "switch";
i++;

name[i]            = "Symantec Reporter";
confidence[i]      = 70;
issuer_org_pat[i]  = "^Symantec Reporter$";
issuer_ou_pat[i]   = "^0801482058$";
subject_org_pat[i] = "^Symantec Reporter$";
subject_ou_pat[i]  = "^0801482058$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Symantec Content Analysis";
confidence[i]      = 70;
issuer_org_pat[i]  = "^Symantec Corporation$";
subject_org_pat[i] = "^Symantec Corporation$";
subject_ou_pat[i]  = "^Content Analysis$";
issuer_ou_pat[i]   = "^Content Analysis$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Quest DR Series Appliance";
issuer_org_pat[i]  = "^DR Series$";
issuer_ou_pat[i]   = "^DR Series$";
subject_org_pat[i] = "^DR Series$";
subject_ou_pat[i]  = "^DR Series$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Super Micro";
confidence[i]      = 75;
issuer_cn_pat[i]   = "^IPMI$";
# should match both 'Super Micro Computer' and 'Super Micro Computer Inc.'
issuer_org_pat[i]  = "^Super Micro Computer";
# should match both 'Software' and 'Software Department'
issuer_ou_pat[i]   = "^Software";
subject_cn_pat[i]  = "^IPMI$";
# should match both 'Super Micro Computer' and 'Super Micro Computer Inc.'
subject_org_pat[i] = "^Super Micro Computer";
# should match both 'Software' and 'Software Department'
subject_ou_pat[i]  = "^Software";
dev_type[i]        = "embedded";
i++;

name[i]            = "Zinwave Series 3000 DAS";
issuer_cn_pat[i]   = "^zinwave$";
issuer_org_pat[i]  = "^ZinWave Ltd$";
issuer_ou_pat[i]   = "^ZinWave Ltd$";
subject_cn_pat[i]  = "^zinwave$";
subject_org_pat[i] = "^ZinWave Ltd$";
subject_ou_pat[i]  = "^ZinWave Ltd$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Symantec Management Center";
issuer_org_pat[i]  = "^Blue Coat Management Center$";
subject_org_pat[i] = "^Blue Coat Management Center$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Veritas NetBackup Appliance";
confidence[i]      = 75; # Lower confidence since 'NetBackup' is not present
issuer_org_pat[i]  = "^Veritas Technologies LLC$";
issuer_ou_pat[i]   = "^Appliance Solutions$";
subject_org_pat[i] = "^Veritas Technologies LLC$";
subject_ou_pat[i]  = "^Appliance Solutions$";
dev_type[i]        = "embedded";
i++;

default_confidence = 90;
default_type = "embedded";
n = i;

fingerprint = "";
foreach var port (ports)
{
  if (!get_port_state(port)) continue;

  cert = get_server_cert(port:port, encoding:"der");
  if (isnull(cert)) continue;
  sha1 = hexstr(SHA1(cert));

  cert = parse_der_cert(cert:cert);
  if (isnull(cert)) continue;

  tbs = cert["tbsCertificate"];
  issuer_seq = tbs["issuer"];
  subject_seq = tbs["subject"];

  issuer = make_array();
  foreach var seq (issuer_seq)
  {
    o = oid_name[seq[0]];
    if (!isnull(o)) issuer[o] = seq[1];
  }

  subject = make_array();
  foreach seq (subject_seq)
  {
    o = oid_name[seq[0]];
    if (!isnull(o)) subject[o] = seq[1];
  }

  if ( strlen(fingerprint) < 256 )
  {
   if (issuer["Common Name"])        fingerprint += "i/CN:" + issuer["Common Name"];
   if (issuer["Organization"])       fingerprint += "i/O:" + issuer["Organization"];
   if (issuer["Organization Unit"])  fingerprint += "i/OU:" + issuer["Organization Unit"];
   if (subject["Common Name"])       fingerprint += "s/CN:" + subject["Common Name"];
   if (subject["Organization"])      fingerprint += "s/O:" + subject["Organization"];
   if (subject["Organization Unit"]) fingerprint += "s/OU:" + subject["Organization Unit"];
   fingerprint += '\n' + sha1 + '\n';
  }

  for (i=0; i<n; i++)
  {
    if (
      (
        !issuer_cn_pat[i] ||
        (issuer["Common Name"] && pregmatch(pattern:issuer_cn_pat[i], string:issuer["Common Name"]))
      ) &&
      (
        !issuer_org_pat[i] ||
        (issuer["Organization"] && pregmatch(pattern:issuer_org_pat[i], string:issuer["Organization"]))
      ) &&
      (
        !issuer_ou_pat[i] ||
        (issuer["Organization Unit"] && pregmatch(pattern:issuer_ou_pat[i], string:issuer["Organization Unit"]))
      ) &&
      (
        !subject_cn_pat[i] ||
        (subject["Common Name"] && pregmatch(pattern:subject_cn_pat[i], string:subject["Common Name"]))
      ) &&
      (
        !subject_org_pat[i] ||
        (subject["Organization"] && pregmatch(pattern:subject_org_pat[i], string:subject["Organization"]))
      ) &&
      (
        !subject_ou_pat[i] ||
        (subject["Organization Unit"] && pregmatch(pattern:subject_ou_pat[i], string:subject["Organization Unit"]))
      )
    )
    {
      if (confidence[i]) confidence = confidence[i];
      else confidence = default_confidence;

      if (dev_type[i]) device_type = dev_type[i];
      else device_type = default_type;

      set_kb_item(name:"Host/OS/SSLcert", value:name[i]);
      set_kb_item(name:"Host/OS/SSLcert/Confidence", value:confidence);
      set_kb_item(name:"Host/OS/SSLcert/Type", value:dev_type[i]);
      exit(0);
    }
  }
}
if ( strlen(fingerprint) > 0 ) set_kb_item(name:"Host/OS/SSLcert/Fingerprint", value:fingerprint);
exit(0, "Nessus was not able to identify the OS from any SSL certificates it uses.");
