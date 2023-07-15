#TRUSTED a8b8d02afc20b1ee76a515dd8674068655a159fe3fe9785f4f0deecbfc9384de63b95ebda6782a25216081285ad4f27244ca6cd68bf3d503d61b931c083cda46b1604f33d621fd6a9920abef470ebf5f762d90929626c27836d0d7af45c325b6bb5b90ed341bb97f845fda754767015a137c13e41d242045c9a7a30689d2caf99c943cd1f8e775b6814e21e11920ec94a28562a6c3d36ca5999d226b2f9f6782e3bca27d0f1b6d7ffbc150ffb5f4037f616b6ec65b73401aac7ab61af57e3ed0082a85d411a98f95e0130dd014982a82f5edd7a95c164d19b5c1383ae1f782ab67bbfdd60a4e6bf6a1df5c75090a66614c4d53c69414df4fd79e0a8676ae9ccea4a5cc5ce5f1cba9a226679e247c0a268a91a80ad96a396a8a843790fcb419706a274a6d8784aac99135274d83e428176cd622df623d3f9193e2ddc0c2f19c0f7c58ebd77057df395ecb908b1100715eb8a97ab5dcca048af85e7776e3edeaf5e7f72ed02c105a7e8a75879515a8b8e543b627cdbcae9e769e89f5b92f64127b61672e19ad25adb1f751c7d7484209698e8dfc0541d67b6a403e023f379cd52dc052f8e90e68d3ac4f2c1ab4fa723fc07574c63ff102c3a91a5e172a2fd482dc7851bf0e8c817801f2b3b11f964e4a029a1ac415fab0e07e700d66b161a3a82d8cea4168ff3c4dc78f41cd4dbd1188b328a342f89e9b1611de7e896c640cb14c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142425);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/05");

  script_cve_id("CVE-2020-3517");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt46838");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt46877");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-nxos-cfs-dos-dAmnymbd");

  script_name(english:"Cisco NX-OS Software (UCS) Software Cisco Fabric Services DoS (cisco-sa-fxos-nxos-cfs-dos-dAmnymbd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco UCS instance NX-OS Software is affected by a denial of service (DoS)
vulnerability. It exists in Cisco fabric services due to insufficient error handling of Cisco fabric service messages. 
An unauthenticated, remote attacker can exploit this issue, via sending crafted Cisco fabric service messages to an 
affected device, resulting in a Denial of Service event.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-nxos-cfs-dos-dAmnymbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?947dee6e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt46838");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt46877");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt46838, CSCvt46877");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('cisco_func.inc');
include('http.inc');
include('install_func.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'cisco_ucs_manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = tolower(install['version']);

vuln = FALSE;

if(cisco_gen_ver_compare(a:version, b:'3.2(3o)') < 0
  )
{
  vuln = TRUE;
}
else if(cisco_gen_ver_compare(a:version, b:'4.0') >= 0 &&
    cisco_gen_ver_compare(a:version, b:'4.0(4i)') < 0
  )
{
  vuln = TRUE;
}
else if(cisco_gen_ver_compare(a:version, b:'4.1') >= 0 &&
    cisco_gen_ver_compare(a:version, b:'4.1(1c)') < 0
  )
{
  vuln = TRUE;
}


{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor advisory.' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);