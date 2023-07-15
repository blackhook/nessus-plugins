#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157867);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/01");

  script_cve_id(
    "CVE-2021-46659",
    "CVE-2021-46663",
    "CVE-2022-24048",
    "CVE-2022-24050",
    "CVE-2022-24051",
    "CVE-2022-24052"
  );

  script_name(english:"FreeBSD : MariaDB -- Multiple vulnerabilities (ff5606f7-8a45-11ec-8be6-d4c9ef517024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the ff5606f7-8a45-11ec-8be6-d4c9ef517024 advisory.

  - MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT statements.
    (CVE-2021-46663)

  - MariaDB before 10.7.2 allows an application crash because it does not recognize that
    SELECT_LEX::nest_level is local to each VIEW. (CVE-2021-46659)

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16191.
    (CVE-2022-24048)

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of validating the existence of an object prior to
    performing operations on the object. An attacker can leverage this vulnerability to escalate privileges
    and execute arbitrary code in the context of the service account. Was ZDI-CAN-16207. (CVE-2022-24050)

  - This vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of a user-supplied string before
    using it as a format specifier. An attacker can leverage this vulnerability to escalate privileges and
    execute arbitrary code in the context of the service account. Was ZDI-CAN-16193. (CVE-2022-24051)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/cve/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10333-rn/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10423-rn/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10514-rn/");
  # https://vuxml.freebsd.org/freebsd/ff5606f7-8a45-11ec-8be6-d4c9ef517024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfcea80e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb104-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb104-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb105-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb105-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'mariadb103-client<10.3.33',
    'mariadb103-server<10.3.33',
    'mariadb104-client<10.4.23',
    'mariadb104-server<10.4.23',
    'mariadb105-client<10.5.14',
    'mariadb105-server<10.5.14'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
