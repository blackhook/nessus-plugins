#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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
  script_id(45571);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2010-0283", "CVE-2010-0628");
  script_bugtraq_id(38260, 38904);

  script_name(english:"FreeBSD : krb5 -- multiple denial of service vulnerabilities (9ac0f9c4-492b-11df-83fb-0015587e2cc1)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities in krb5 can be used by remote attackers in denial
of service attacks. The MIT security advisories report this as follows
:

An unauthenticated remote attacker can send an invalid request to a
KDC process that will cause it to crash due to an assertion failure,
creating a denial of service.

An unauthenticated remote attacker could cause a GSS-API application,
including the Kerberos administration daemon (kadmind) to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-001.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-002.txt"
  );
  # https://vuxml.freebsd.org/freebsd/9ac0f9c4-492b-11df-83fb-0015587e2cc1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb100eb8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"krb5>=1.7<=1.7_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
