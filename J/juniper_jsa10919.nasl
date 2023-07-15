#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121069);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2018-0732", "CVE-2018-0737");
  script_xref(name:"JSA", value:"JSA10919");

  script_name(english:"Junos OS: OpenSSL Security Advisories [16 Apr 2018] and [12 June 2018] (JSA10919)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a multiple vulnerabilities:

- During key agreement in a TLS handshake using a DH(E) based 
  ciphersuite a malicious server can send a very large prime value to
  the client. This will cause the client to spend an unreasonably 
  long period of time generating a key for this prime resulting in a
  hang until the client has finished. This could be exploited in a 
  Denial Of Service attack. Fixed in OpenSSL 1.1.0i-dev (Affected 
  1.1.0-1.1.0h). Fixed in OpenSSL 1.0.2p-dev (Affected 1.0.2-1.0.2o).
  (CVE-2018-0732)
  
- The OpenSSL RSA Key generation algorithm has been shown to be 
  vulnerable to a cache timing side channel attack. An attacker with
  sufficient access to mount cache timing attacks during the RSA key
  generation process could recover the private key. Fixed in OpenSSL
  1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in OpenSSL 1.0.2p-dev
  (Affected 1.0.2b-1.0.2o). (CVE-2018-0737)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10919");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10919.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.3X48'] = '12.3X48-D77';
fixes['15.1'] = '15.1F6-S12';
fixes['15.1X49'] = '15.1X49-D160';
fixes['15.1X53'] = '15.1X53-D68';
fixes['16.1'] = '16.1R3-S10';
fixes['16.1X65'] = '16.1X65-D49';
fixes['16.2'] = '16.2R2-S8';
fixes['17.1'] = '17.1R2-S10';
fixes['17.2'] = '17.2R1-S7';
fixes['17.3'] = '17.3R3-S2';
fixes['17.4'] = '17.4R1-S6';
fixes['18.1'] = '18.1R2-S4';
fixes['18.2'] = '18.2R1-S4';
fixes['18.3'] = '18.3R1-S1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_warning(port:0, extra:report);
}
else security_warning(0);
