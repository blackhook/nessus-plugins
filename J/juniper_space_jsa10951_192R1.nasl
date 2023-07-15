#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131701);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2016-8615",
    "CVE-2016-8616",
    "CVE-2016-8617",
    "CVE-2016-8618",
    "CVE-2016-8619",
    "CVE-2016-8620",
    "CVE-2016-8621",
    "CVE-2016-8622",
    "CVE-2016-8623",
    "CVE-2016-8624",
    "CVE-2016-8625",
    "CVE-2018-10902",
    "CVE-2018-12327",
    "CVE-2019-5739",
    "CVE-2019-6133"
  );
  script_bugtraq_id(
    94094,
    94096,
    94097,
    94098,
    94100,
    94101,
    94102,
    94103,
    94105,
    94106,
    94107,
    104517,
    105119,
    106537
  );

  script_name(english:"Juniper Junos Space < 19.2R1 Multiple Vulnerabilities (JSA10951)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 19.2R1. It is, therefore, affected by multiple
vulnerabilities:
    - A memory double free vulnerability exists in The libcurl API function called `curl_maprintf()` before version 7.51.0 
      due to an unsafe `size_t` multiplication, on systems using 32 bit `size_t` variables. An unauthiticated remote attacker
      can leverage this issue to perform unauthorized actions. This may aid in further attacks. (CVE-2016-8618) 

    - A denial of service (DoS) vulnerability exists in Node.js 6.16.0 and earlier due to that Keep-alive HTTP and HTTPS 
      connections can remain open and inactive for up to 2 minutes. An unauthenticated, remote attacker can exploit this
      issue to cause a denial of service. (CVE-2016-8619)
      
    - A vulnerability in curl before version 7.51.0 due to the use of an outdated IDNA 2003 standard to handle International
      Domain Names. This could lead users to unknowingly issue network transfer requests to the wrong host. (CVE-2016-8625)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10951");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space 19.2R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8618");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'19.2R1', severity:SECURITY_HOLE);
