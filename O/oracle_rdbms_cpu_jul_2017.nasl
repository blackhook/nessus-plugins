#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101836);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2016-2183",
    "CVE-2017-10120",
    "CVE-2017-10202"
  );
  script_bugtraq_id(70574, 92630);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2017 CPU) (POODLE) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the July 2017 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

 -  An unspecified vulnerability exists in the RDBMS
    Security component that allows a local attacker to
    impact integrity. Note that the attacker would need to
    have Create Session or Select Any Dictionary privileges.
    (CVE-2017-10120)

  - An unspecified vulnerability exists in the OJVM
    component that allows an authenticated, remote attacker
    to impact confidentiality, integrity, and availability.
    Note that the attacker would need to have Create
    Session or Create Procedure privileges. (CVE-2017-10202)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10202");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

patches = make_nested_array();
# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.170718", "CPU", "26123830, 26609817, 26710464, 27105253, 27674384, 28163133, 28662603");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.170718", "CPU", "26204212");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.170718", "CPU", "25755742, 26022196, 26609783, 26610308, 26610322"); # 26610308 is a system patch
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.170718", "CPU", "26161724, 26161726");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.170718", "CPU", "25879656, 25869727, 26609445");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.170718", "CPU", "26194136");


# JVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.170718", "CPU", "25811364");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.170718", "CPU", "26182467");
# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.170718", "CPU", "26027162");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.170718", "CPU", "26182439");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.170718", "CPU", "26027154");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.170718", "CPU", "26182425");

check_oracle_database(patches:patches);

