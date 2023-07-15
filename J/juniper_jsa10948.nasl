#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132038);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2018-15504", "CVE-2018-15505");
  script_xref(name:"JSA", value:"JSA10948");

  script_name(english:"Juniper Embedthis GoAhead Denial Of Service Vulnerabilities (JSA10948)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 12.3R12-S14, 12.3X48-D80, 15.1F6-S13, 15.1X49-D170,
15.1X53-D497, 16.1R4-S13, 16.2R2-S10, 17.1R3, 17.2R2-S7, 17.3R3-S5, 17.4R1-S7, or 18.1R3-S5. It is, therefore, affected
by multiple vulnerabilities as referenced in the JSA10948 advisory:
	- A denial of service (DoS) vulnerability exists in Embedthis GoAhead before 4.0.1 and Appweb before 7.0.2 due to 
      An HTTP POST request with a specially crafted 'Host' header field may cause a NULL pointer dereference and thus 
      cause a denial of service as demonstrated by the lack of a trailing ']' character in an IPv6 address. An 
      unauthenticated, remote attacker can exploit this to conduct a  denial of service attack on an arbitrary remote 
      host. (CVE-2018-15505)
      
    - A denial of service (DoS) vulnerability exists in Embedthis GoAhead before 4.0.1 and Appweb before 7.0.2 due to 
      An HTTP POST request with a specially crafted 'Host' header field may cause a NULL pointer dereference and thus 
      cause a denial of service as demonstrated by If-Modified-Since or If-Unmodified-Since with a month greater than
      11. An unauthenticated, remote attacker can exploit this to conduct a  denial of service attack on an arbitrary
      remote host. (CVE-2018-15504)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10948");
  script_set_attribute(attribute:"solution", value:
"Disable J-Web, limit access to only trusted hosts or apply the relevant Junos software
release referenced in Juniper advisory JSA10948");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15505");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.3'] = '12.3R12-S14';
fixes['12.3X48'] = '12.3X48-D80';
fixes['15.1R'] = '15.1R7-S4';
fixes['15.1F'] = '15.1F6-S13';
fixes['15.1X49'] = '15.1X49-D170';
fixes['15.1X53'] = '15.1X53-D497';
fixes['16.1'] = '16.1R4-S13';
fixes['16.2'] = '16.2R2-S10';
fixes['17.1'] = '17.1R3';
fixes['17.2'] = '17.2R2-S7';
fixes['17.3'] = '17.3R3-S5';
fixes['17.4'] = '17.4R1-S7';
fixes['18.1'] = '18.1R3-S5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
