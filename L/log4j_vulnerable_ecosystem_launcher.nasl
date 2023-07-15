#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

var script_names_filenames = {
  "155998 Apache Log4j Message Lookup Substitution RCE (Log4Shell) (Direct Check)": "apache_log4j_jdni_ldap_generic.nbin",
  "155999 Apache Log4j < 2.15.0 Remote Code Execution": "apache_log4j_2_15_0.nasl",
  "156000 Apache Log4j Installed (Unix)": "apache_log4j_nix_installed.nbin",
  "156001 Apache Log4j JAR Detection (Windows)": "apache_log4j_win_installed.nbin",
  "156002 Apache Log4j < 2.15.0 Remote Code Execution": "apache_log4j_win_2_15_0.nasl",
  "156014 Apache Log4Shell RCE detection via callback correlation (Direct Check HTTP)": "apache_log4j_jdni_ldap_generic_http_headers.nbin",
  "156017 SIP Script Remote Command Execution via log4shell": "log4j_log4shell_sip_invite.nbin",
  "156016 Apache Log4Shell RCE detection via Path Enumeration (Direct Check HTTP)": "log4j_log4shell_www.nbin",
  "156035 VMware vCenter Log4Shell Direct Check (CVE-2021-44228) (VMSA-2021-0028)": "vmware_vcenter_log4shell.nbin",
  "156032 Log4j EOL / Unsupported Apache Log4j Unsupported Version Detection": "apache_log4j_unsupported.nasl",
  "156056 Apache Log4Shell RCE detection via Raw Socket Logging (Direct Check)": "apache_log4j_jndi_ldap_generic_raw.nbin",
  "156057 Apache Log4j 2.x < 2.16.0 RCE": "apache_log4j_2_16_0.nasl",
  "156103 Apache Log4j 1.2 JMSAppender Remote Code Execution (CVE-2021-4104)": "apache_log4j_1_2.nasl",
  "156157 Apache Log4Shell RCE detection via callback correlation (Direct Check POP3)": "apache_log4j_jdni_ldap_generic_telnet.nbin",
  "156157 Apache Log4Shell RCE detection via callback correlation (Direct Check IMAP)": "apache_log4shell_pop3.nbin",
  "156158 Apache Log4Shell RCE detection via callback correlation (Direct Check Telnet)": "apache_log4shell_imap.nbin",
  "156132 Apache Log4Shell RCE detection via callback correlation (Direct Check SMTP)": "apache_log4shell_smtp.nbin",
  "156164 Apache Log4Shell CVE-2021-45046 Bypass Remote Code Execution": "apache_log4shell_CVE-2021-45056_direct_check.nbin",
  "156112 Amazon Linux 2 : aws-kinesis-agent (ALAS-2021-1730)": "al2_ALAS-2021-1730.nasl",
  "156124 Debian DSA-5022-1 : apache-log4j2 - security update": "debian_DSA-5022.nasl",
  "156104 Ubuntu 20.04 LTS : Apache Log4j 2 vulnerability (USN-5197-1)": "ubuntu_USN-5197-1.nasl",
  "156018 Debian DLA-2842-1 : apache-log4j2 - LTS security update": "debian_DLA-2842.nasl",
  "156015 Debian DSA-5020-1 : apache-log4j2 - security update": "debian_DSA-5020.nasl",
  "156021 FreeBSD : graylog -- include log4j patches (3fadd7e4-f8fb-45a0-a218-8fd6423c338f)": "freebsd_pkg_3fadd7e4f8fb45a0a2188fd6423c338f.nasl",
  "156026 FreeBSD : OpenSearch -- Log4Shell (4b1ac5a3-5bd4-11ec-8602-589cfc007716)": "freebsd_pkg_4b1ac5a35bd411ec8602589cfc007716.nasl",
  "156078 FreeBSD : serviio -- affected by log4j vulnerability (1ea05bb8-5d74-11ec-bb1e-001517a2e1a4)": "freebsd_pkg_1ea05bb85d7411ecbb1e001517a2e1a4.nasl",
  "156054 Ubuntu 18.04 LTS / 20.04 LTS : Apache Log4j 2 vulnerability (USN-5192-1)": "ubuntu_USN-5192-1.nasl",
  "156052 FreeBSD : bastillion -- log4j vulnerability (515df85a-5cd7-11ec-a16d-001517a2e1a4)": "freebsd_pkg_515df85a5cd711eca16d001517a2e1a4.nasl",
  "156115 Apache Log4Shell RCE detection via callback correlation (Direct Check FTP)": "log4j_log4shell_ftp.nbin",
  "156166 Apache Log4Shell RCE detection via callback correlation (Direct Check SSH)": "apache_log4shell_ssh.nbin",
  "156153 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:4094-1)": "openSUSE-2021-4094.nasl",
  "156139 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:4107-1)": "openSUSE-2021-4107.nasl",
  "156165 Apache Log4j 2.x < 2.16.0 RCE (MacOS)": "apache_log4j_2_16_0_mac.nasl",
  "156146 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:1577-1)": "openSUSE-2021-1577.nasl",
  "156150 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:1586-1)": "openSUSE-2021-1586.nasl",
  "156145 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:3999-1)": "openSUSE-2021-3999.nasl",
  "156161 Ubuntu 16.04 LTS : Apache Log4j 2 vulnerability (USN-5192-2)": "ubuntu_USN-5192-2.nasl",
  "156183 Apache Log4j 2.x < 2.17.0 DoS": "apache_log4j_2_17_0.nasl",
  "156175 Amazon Linux 2 : java-1.8.0-amazon-corretto (ALAS-2021-001)": "al2_ALAS-2021-001.nasl",
  "156174 Amazon Linux AMI : java-1.8.0-openjdk, java-1.7.0-openjdk, java-1.6.0-openjdk (ALAS-2021-1553)": "ala_ALAS-2021-1553.nasl",
  "156182 Amazon Linux 2 : java-17-amazon-corretto, java-11-amazon-corretto, java-1.8.0-openjdk, java-1.7.0-openjdk (ALAS-2021-1731)": "al2_ALAS-2021-1731.nasl",
  "156180 openSUSE 15 Security Update : logback (openSUSE-SU-2021:4109-1)": "openSUSE-2021-4109.nasl",
  "156177 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:4111-1)": "openSUSE-2021-4111.nasl",
  "156181 openSUSE 15 Security Update : log4j12 (openSUSE-SU-2021:4112-1)": "openSUSE-2021-4112.nasl",
  "156167 SUSE SLES11 Security Update : log4j (SUSE-SU-2021:14866-1)": "suse_SU-2021-14866-1.nasl",
  "156169 SUSE SLES15 Security Update : log4j (SUSE-SU-2021:4111-1)": "suse_SU-2021-4111-1.nasl",
  "156172 SUSE SLED15 / SLES15 Security Update : log4j12 (SUSE-SU-2021:4112-1)": "suse_SU-2021-4112-1.nasl",
  "156170 SUSE SLED12 / SLES12 Security Update : log4j (SUSE-SU-2021:4115-1)": "suse_SU-2021-4115-1.nasl",
  "156197 Apache Log4Shell RCE detection via callback correlation (Direct Check NetBIOS)": "apache_log4shell_netbios.nbin",
  "156206 Oracle Linux 7 : log4j (ELSA-2021-5206)": "oraclelinux_ELSA-2021-5206.nasl",
  "156218 openSUSE 15 Security Update : log4j (openSUSE-SU-2021:1601-1)": "openSUSE-2021-1601.nasl",
  "156210 FreeBSD : graylog -- remote code execution in log4j from user-controlled log input (650734b2-7665-4170-9a0a-eeced5e10a5e)": "freebsd_pkg_650734b2766541709a0aeeced5e10a5e.nasl",
  "156232 Apache Log4Shell RCE detection via callback correlation (Direct Check SMB)": "log4j_log4shell_smb.nbin",
  "156258 Apache Log4Shell RCE detection via callback correlation (Direct Check NTP)": "log4j_log4shell_ntp.nbin",
  "156257 Apache Log4Shell RCE detection via callback correlation (Direct Check DNS)": "apache_log4shell_dns.nbin",
  "156256 Apache Log4Shell RCE detection via callback correlation (Direct Check SNMP)": "apache_log4shell_snmp.nbin",
  "156279 openSUSE 15 Security Update : logback (openSUSE-SU-2021:1613-1)": "openSUSE-2021-1613.nasl",
  "156276 openSUSE 15 Security Update : log4j12 (openSUSE-SU-2021:1612-1)": "openSUSE-2021-1612.nasl",
  "156324 FreeBSD : OpenSearch -- Log4Shell (b0f49cb9-6736-11ec-9eea-589cfc007716)": "freebsd_pkg_b0f49cb9673611ec9eea589cfc007716.nasl",
  "156327 Apache Log4j 2.0 < 2.3.2 / 2.4 < 2.12.4 / 2.13 < 2.17.1 RCE": "apache_log4j_2_17_1.nasl",
  "156264 Amazon Linux AMI : log4j-cve-2021-44228-hotpatch (ALAS-2021-1554)": "ala_ALAS-2021-1554.nasl",
  "156375 Apache Log4Shell RCE detection via callback correlation (Direct Check UPnP)": "apache_log4shell_upnp.nbin",
  "156340 openSUSE 15 Security Update : kafka (openSUSE-SU-2021:1631-1)": "openSUSE-2021-1631.nasl",
  "156441 Ubiquiti UniFi Network Log4Shell Direct Check (CVE-2021-44228)": "ubiquiti_unifi_network_log4shell.nbin",
  "156455 Apache Log4Shell RCE detection via callback correlation (Direct Check PPTP)": "log4j_log4shell_pptp.nbin",
  "156471 Apache Solr Log4Shell Direct Check (CVE-2021-44228)": "apache_solr_log4shell.nbin",
  "156473 Apache OFBiz Log4Shell Direct Check (CVE-2021-44228)": "apache_ofbiz_log4shell.nbin",
  "156560 VMware Horizon Log4Shell Direct Check (CVE-2021-44228) (VMSA-2021-0028)": "vmware_horizon_log4shell.nbin",
  "156558 Apache JSPWiki Log4Shell Direct Check (CVE-2021-44228)": "apache_jspwiki_log4shell.nbin",
  "156559 Apache Log4Shell RCE detection via callback correlation (Direct Check RPCBIND)": "log4j_log4shell_rpcbind.nbin",
  "156669 Apache Log4Shell RCE detection via callback correlation (Direct Check MSRPC)": "apache_log4shell_msrpc.nbin",
  "156712 Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : Apache Log4j 1.2 vulnerability (USN-5223-1)": "ubuntu_USN-5223-1.nasl",
  "156753 Apache Druid Log4Shell Direct Check (CVE-2021-44228)": "apache_druid_log4shell.nbin",
  "156893 Oracle Primavera Gateway (Jan 2022 CPU)": "oracle_primavera_gateway_cpu_jan_2022.nasl",
  "156891 Oracle Primavera P6 Enterprise Project Portfolio Management (Jan 2022 CPU)": "oracle_primavera_p6_eppm_cpu_jan_2022.nasl",
  "156871 Amazon Linux AMI : log4j (ALAS-2022-1562)": "ala_ALAS-2022-1562.nasl",
  "156932 VMware vRealize Operations Manager Log4Shell Direct Check (CVE-2021-44228) (VMSA-2021-0028)": "vmware_vrealize_operations_manager_log4shell.nbin",
  "156941 MobileIron Core Log4Shell Direct Check (CVE-2021-44228)": "mobileiron_log4shell.nbin",
  "157137 Oracle Linux 6 : log4j (ELSA-2022-9056)": "oraclelinux_ELSA-2022-9056.nasl",
  "157159 Oracle Linux 8 : parfait:0.5 (ELSA-2022-0290)": "oraclelinux_ELSA-2022-0290.nasl"
};

var bullet_point_names_list = '';
foreach name (keys(script_names_filenames)) {
  bullet_point_names_list += ' - ' + name + '\n';
}

if (description)
{
  script_id(156061);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_name(english:"Log4Shell Ecosystem Wrapper");

  script_set_attribute(attribute:"synopsis", value:
"This plugin serves as a launcher plugin for plugins in the Apache Log4j vulnerable ecosystem.");
  script_set_attribute(attribute:"description", value:
"This plugin was used in the scan template 'Log4Shell Vulnerability Ecosystem' (prior to 2/2/2022) as a way to include other plugins related
to the Log4j vulnerabilities CVE-2021-44228, CVE-2021-44832, CVE-2021-45046, and CVE-2021-4104, including those based 
on patches from other vendors." + '\n' + bullet_point_names_list + '\n');
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  foreach dep (script_names_filenames) {
    script_dependencies(dep);
  }

  exit(0);
}

exit(0);
