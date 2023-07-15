#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
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
  script_id(148748);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-13956", "CVE-2021-26291");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"FreeBSD : Apache Maven -- multiple vulnerabilities (20006b5f-a0bc-11eb-8ae6-fc4dd43e2b6a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The Apache Maven project reports :

We received a report from Jonathan Leitschuh about a vulnerability of
custom repositories in dependency POMs. We've split this up into three
separate issues :

- Possible Man-In-The-Middle-Attack due to custom repositories using
HTTP.

More and more repositories use HTTPS nowadays, but this hasn't always
been the case. This means that Maven Central contains POMs with custom
repositories that refer to a URL over HTTP. This makes downloads via
such repository a target for a MITM attack. At the same time,
developers are probably not aware that for some downloads an insecure
URL is being used. Because uploaded POMs to Maven Central are
immutable, a change for Maven was required. To solve this, we extended
the mirror configuration with blocked parameter, and we added a new
external:http:* mirror selector (like existing external:*), meaning
'any external URL using HTTP'.

The decision was made to block such external HTTP repositories by
default : this is done by providing a mirror in the conf/settings.xml
blocking insecure HTTP external URLs.

- Possible Domain Hijacking due to custom repositories using abandoned
domains

Sonatype has analyzed which domains were abandoned and has claimed
these domains.

- Possible hijacking of downloads by redirecting to custom
repositories

This one was the hardest to analyze and explain. The short story is :
you're safe, dependencies are only downloaded from repositories within
their context. So there are two main questions: what is the context
and what is the order? The order is described on the Repository Order
page. The first group of repositories are defined in the settings.xml
(both user and global). The second group of repositories are based on
inheritence, with ultimately the super POM containing the URL to Maven
Central. The third group is the most complex one but is important to
understand the term context: repositories from the effective POMs from
the dependency path to the artifact. So if a dependency was defined by
another dependency or by a Maven project, it will also include their
repositories. In the end this is not a bug, but a design feature.");
  script_set_attribute(attribute:"see_also", value:"http://maven.apache.org/docs/3.8.1/release-notes.html#cve-2021-26291");
  # https://vuxml.freebsd.org/freebsd/20006b5f-a0bc-11eb-8ae6-fc4dd43e2b6a.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db7a98a5");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:maven");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"maven<3.8.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
