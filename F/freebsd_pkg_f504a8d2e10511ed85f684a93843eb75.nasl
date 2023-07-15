#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(174664);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/24");

  script_cve_id(
    "CVE-2022-37434",
    "CVE-2023-21911",
    "CVE-2023-21912",
    "CVE-2023-21913",
    "CVE-2023-21917",
    "CVE-2023-21919",
    "CVE-2023-21920",
    "CVE-2023-21929",
    "CVE-2023-21933",
    "CVE-2023-21935",
    "CVE-2023-21940",
    "CVE-2023-21945",
    "CVE-2023-21946",
    "CVE-2023-21947",
    "CVE-2023-21953",
    "CVE-2023-21955",
    "CVE-2023-21962",
    "CVE-2023-21963",
    "CVE-2023-21966",
    "CVE-2023-21971",
    "CVE-2023-21972",
    "CVE-2023-21976",
    "CVE-2023-21977",
    "CVE-2023-21980",
    "CVE-2023-21982"
  );

  script_name(english:"FreeBSD : MySQL -- Multiple vulnerabilities (f504a8d2-e105-11ed-85f6-84a93843eb75)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the f504a8d2-e105-11ed-85f6-84a93843eb75 advisory.

  - zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a
    large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some
    common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g.,
    see the nodejs/node reference). (CVE-2022-37434)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. (CVE-2023-21911)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.41 and prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2023-21912)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21913)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21917)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21919, CVE-2023-21933)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21920, CVE-2023-21935, CVE-2023-21945, CVE-2023-21976, CVE-2023-21977,
    CVE-2023-21982)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. (CVE-2023-21929)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2023-21940, CVE-2023-21947)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21946)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Partition). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21953, CVE-2023-21955)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2023-21962)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Connection Handling).
    Supported versions that are affected are 5.7.40 and prior and 8.0.31 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of MySQL Server. (CVE-2023-21963)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: JSON). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21966)

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions
    that are affected are 8.0.32 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Connectors. Successful attacks require
    human interaction from a person other than the attacker. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Connectors as well as unauthorized update, insert or delete access to some of MySQL Connectors accessible
    data and unauthorized read access to a subset of MySQL Connectors accessible data. (CVE-2023-21971)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21972)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Client programs). Supported versions
    that are affected are 5.7.41 and prior and 8.0.32 and prior. Difficult to exploit vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in takeover of MySQL Server. (CVE-2023-21980)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixMSQL");
  # https://vuxml.freebsd.org/freebsd/f504a8d2-e105-11ed-85f6-84a93843eb75.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8a99fd3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql-client57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql-client80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql-connector-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql-server57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql-server80");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'mysql-client57<5.7.42',
    'mysql-client80<8.0.33',
    'mysql-connector-java<8.0.33',
    'mysql-server57<5.7.42',
    'mysql-server80<8.0.33'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
