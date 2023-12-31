#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90834);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/03");

  script_cve_id(
    "CVE-2015-3197",
    "CVE-2016-0639",
    "CVE-2016-0642",
    "CVE-2016-0643",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0655",
    "CVE-2016-0657",
    "CVE-2016-0659",
    "CVE-2016-0662",
    "CVE-2016-0666",
    "CVE-2016-0667",
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800",
    "CVE-2016-2047",
    "CVE-2016-3440",
    "CVE-2016-5444",
    "CVE-2017-10378"
  );
  script_bugtraq_id(
    81810,
    82237,
    83705,
    83733,
    83754,
    83755,
    83763,
    86418,
    86424,
    86433,
    86445,
    86457,
    86484,
    86486,
    86493,
    86495,
    86506,
    86509,
    91910,
    91987,
    101375
  );
  script_xref(name:"CERT", value:"257823");
  script_xref(name:"CERT", value:"583776");

  script_name(english:"Oracle MySQL 5.7.x < 5.7.12 Multiple Vulnerabilities (RPM Check) (April 2016 CPU) (July 2016 CPU) (October 2017 CPU) (DROWN)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.7.x
prior to 5.7.12. It is, therefore, affected by the following
vulnerabilities :

  - A cipher algorithm downgrade vulnerability exists in the
    bundled version of OpenSSL due to a flaw that is
    triggered when handling cipher negotiation. A remote
    attacker can exploit this to negotiate SSLv2 ciphers and
    complete SSLv2 handshakes even if all SSLv2 ciphers have
    been disabled on the server. Note that this
    vulnerability only exists if the SSL_OP_NO_SSLv2 option
    has not been disabled. (CVE-2015-3197)

  - An unspecified flaw exists in the Pluggable
    Authentication subcomponent that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-0639)

  - An unspecified flaw exists in the Federated subcomponent
    that allows a local attacker to impact integrity and
    availability. (CVE-2016-0642)

  - An unspecified flaw exists in the DML subcomponent that
    allows a local attacker to disclose potentially
    sensitive information. (CVE-2016-0643)

  - An unspecified flaw exists in the FTS subcomponent that
    allows a local attacker to cause a denial of service
    condition. (CVE-2016-0647)

  - An unspecified flaw exists in the PS subcomponent that
    allows a local attacker to cause a denial of service
    condition. (CVE-2016-0648)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows a local attacker to cause a denial of
    service condition. (CVE-2016-0655)

  - An unspecified flaw exists in the JSON subcomponent that
    allows a local attacker to disclose potentially
    sensitive information. (CVE-2016-0657)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows a local attacker to cause a denial of
    service condition. (CVE-2016-0659)

  - An unspecified flaw exists in the Partition subcomponent
    that allows a local attacker to cause a denial of
    service condition. (CVE-2016-0662)

  - An unspecified flaw exists in the Security: Privileges
    subcomponent that allows a local attacker to cause a
    denial of service condition. (CVE-2016-0666)

  - An unspecified flaw exists in the Locking subcomponent
    that allows a local attacker to cause a denial of
    service condition. (CVE-2016-0667)

  - A key disclosure vulnerability exists in the bundled
    version of OpenSSL due to improper handling of
    cache-bank conflicts on the Intel Sandy-bridge
    microarchitecture. An attacker can exploit this to gain
    access to RSA key information. (CVE-2016-0702)

  - A double-free error exists in the bundled version of
    OpenSSL due to improper validation of user-supplied
    input when parsing malformed DSA private keys. A remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0705)

  - A NULL pointer dereference flaw exists in the bundled
    version of OpenSSL in the BN_hex2bn() and BN_dec2bn()
    functions. A remote attacker can exploit this to trigger
    a heap corruption, resulting in the execution of
    arbitrary code. (CVE-2016-0797)

  - A denial of service vulnerability exists in the bundled
    version of OpenSSL due to improper handling of invalid
    usernames. A remote attacker can exploit this, via a
    specially crafted username, to leak 300 bytes of memory
    per connection, exhausting available memory resources.
    (CVE-2016-0798)

  - Multiple memory corruption issues exist in the bundled
    version of OpenSSL that allow a remote attacker to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0799)

  - A flaw exists in the bundled version of OpenSSL that
    allows a cross-protocol Bleichenbacher padding oracle
    attack known as DROWN (Decrypting RSA with Obsolete and
    Weakened eNcryption). This vulnerability exists due to a
    flaw in the Secure Sockets Layer Version 2 (SSLv2)
    implementation, and it allows captured TLS traffic to be
    decrypted. A man-in-the-middle attacker can exploit this
    to decrypt the TLS connection by utilizing previously
    captured traffic and weak cryptography along with a
    series of specially crafted connections to an SSLv2
    server that uses the same private key. (CVE-2016-0800)

  - A man-in-the-middle spoofing vulnerability exists due to
    the server hostname not being verified to match a domain
    name in the Subject's Common Name (CN) or SubjectAltName
    field of the X.509 certificate. A man-in-the-middle
    attacker can exploit this, by spoofing the TLS/SSL
    server via a certificate that appears valid, to disclose
    sensitive information or manipulate transmitted data.
    (CVE-2016-2047)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allow an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3440,
    CVE-2017-10378)

  - An unspecified flaw exists in the Connection
    subcomponent that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    (CVE-2016-5444)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2948264.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae0f7f52");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3089849.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42cde00c");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3937099.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9f2a38");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-12.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2120034.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2157431.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2307762.1");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb7b96f");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0799");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.7.12";
exists_version = "5.7";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_HOLE);
