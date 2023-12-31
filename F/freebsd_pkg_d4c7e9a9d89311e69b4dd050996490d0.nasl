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
  script_id(96473);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444", "CVE-2016-9778");

  script_name(english:"FreeBSD : BIND -- multiple vulnerabilities (d4c7e9a9-d893-11e6-9b4d-d050996490d0)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISC reports :

A malformed query response received by a recursive server in response
to a query of RTYPE ANY could trigger an assertion failure while named
is attempting to add the RRs in the query response to the cache.

Depending on the type of query and the EDNS options in the query they
receive, DNSSEC-enabled authoritative servers are expected to include
RRSIG and other RRsets in their responses to recursive servers.
DNSSEC-validating servers will also make specific queries for DS and
other RRsets. Whether DNSSEC-validating or not, an error in processing
malformed query responses that contain DNSSEC-related RRsets that are
inconsistent with other RRsets in the same query response can trigger
an assertion failure. Although the combination of properties which
triggers the assertion should not occur in normal traffic, it is
potentially possible for the assertion to be triggered deliberately by
an attacker sending a specially-constructed answer.

An unusually-formed answer containing a DS resource record could
trigger an assertion failure. While the combination of properties
which triggers the assertion should not occur in normal traffic, it is
potentially possible for the assertion to be triggered deliberately by
an attacker sending a specially-constructed answer having the required
properties.

An error in handling certain queries can cause an assertion failure
when a server is using the nxdomain-redirect feature to cover a zone
for which it is also providing authoritative service. A vulnerable
server could be intentionally stopped by an attacker if it was using a
configuration that met the criteria for the vulnerability and if the
attacker could cause it to accept a query that possessed the required
attributes."
  );
  # https://kb.isc.org/article/AA-01439/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01439"
  );
  # https://kb.isc.org/article/AA-01440/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01440"
  );
  # https://kb.isc.org/article/AA-01441/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01441"
  );
  # https://kb.isc.org/article/AA-01442/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01442"
  );
  # https://vuxml.freebsd.org/freebsd/d4c7e9a9-d893-11e6-9b4d-d050996490d0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b699364"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind910");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind911");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"bind99<9.9.9P5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind910<9.10.4P5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind911<9.11.0P2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind9-devel<=9.12.0.a.2016.12.28")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
