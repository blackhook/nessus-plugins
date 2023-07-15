#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124090);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000300",
    "CVE-2018-1000301"
  );
  script_bugtraq_id(
    103414,
    103415,
    103436,
    104207,
    104225
  );

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by vulnerabilities as noted in the October 2018 CPU advisory:

  - A vulnerability exists in the Oracle HTTP Server component
    of Oracle Fusion Middleware (subcomponent: Web Listener
    (curl)). The affected version is 12.2.1.3. This is a 
    difficult to exploit vulnerability that allows an
    unauthenticated attacker with network access via HTTP to
    compromise Oracle HTTP Server. A successful attacks
    requires human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in takeover of Oracle HTTP Server. (CVE-2018-1000300)
    
  - A denial of service (DoS) vulnerability exists in curl due
    to Buffer Over-read. Affected versions are from curl version
    7.20.0 to curl 7.59.0. The vulnerable component can be
    tricked into reading data beyond the end of the heap.
    An unauthenticated attacked with network access can exploit
    this issue to cause the application to stop responding.
    (CVE-2018-1000301)

  - A buffer over-read vulnerability exists in curl that could lead to
    information leakage. Affected versions are from  7.20.0 to
    curl 7.58.0. A vulnerability in the RTSP+RTP handling code
    could allows an attacker to cause a denial of service or
    information leakage. An unauthenticated attacked with 
    network access can exploit this vulnerability to cause
    a denial of service (DoS) or to leak information
    from the vulnerable application.
    (CVE-2018-1000122)");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

install = branch(install_list, key:TRUE, value:TRUE);

patches = make_array();
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.180710', 'patch', '28281599');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
