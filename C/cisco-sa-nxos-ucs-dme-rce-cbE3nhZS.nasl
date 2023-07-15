#TRUSTED 7a749aaa339a616fb7e9bbd2917fdbd3a8cf6c11e7195f2162876492e0cff126e81b07f129c726a3a84bf617cbbd4a1a08b96d38313abddba823f74b2bd9269d2bab0571b18821b1eb6cc9d510eb4a1ed29e6ede805d7aea9b1600333a29d11109123654bc25b170a624e885d221fb60b6a970cf27abab0c895651f85ffc966f113cdedfcf26f683a77855aac64dadbd5d8631ed47fce4cab2c54ef14b7ebbbcdb5918431c217a5b4341f54eaf81a592377b88db324ee597e618e57fe885a6d610ef653b499a59df5eb2b6c9176e44a697191e4d735a3236530dc8da8ef1a5a950c2da1cd0f95a19d46f382e08bdab9876e6640bca43968274aa152102f909d9d071f185676e3679ba8f59221240948ca25f97cc3e6c9a60402f25aa566fb14bf97c314fd3f2c7d46c0484b004ebf427817e4224005f2968a3d0effbd8276afd3dfcfe51120bb66f57b1d1677c3e8e31353c3fc2b30bf874e8a4d0f6770d9b0c78fbb79ec76d04a096803e33de50b12d3fca351a3c0b0e69935d073d4efc237f6fa6556922fd7b017386d5e1fc514fa49e8971ef588c2ebf6594ae71832fb84f1b110a5af046c3e62f6b30bc2eb9b118e32a68dc4dd1995382d035140895c08f1e3ad9f4bd961eca5dbefbdb95ab3841cd8193f31438aa2c915375544d6a4955887eaa5146290784b0d648fc86327347c92012c56026a45b66a512c301340211
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140186);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2020-3415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr89315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-dme-rce-cbE3nhZS");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software (UCS) Data Management Engine Remote Code Execution (cisco-sa-nxos-dme-rce-cbE3nhZS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software (UCS) is affected by a remote code execution vulnerability.
The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a
crafted Cisco Discovery Protocol packet to a Layer 2-adjacent affected device. A successful exploit could allow the
attacker to execute arbitrary code with administrative privileges or cause the Cisco Discovery Protocol process to
crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dme-rce-cbE3nhZS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f83e12a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs10167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr89315");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('cisco_func.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'cisco_ucs_manager';

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = tolower(install['version']);

if ( cisco_gen_ver_compare(a:version, b:'4.0') >= 0 &&
      cisco_gen_ver_compare(a:version, b:'4.0(4h)') < 0
   )

{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor advisory' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);


