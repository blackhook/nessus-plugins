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
  script_id(104693);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-0361",
    "CVE-2017-8808",
    "CVE-2017-8809",
    "CVE-2017-8810",
    "CVE-2017-8811",
    "CVE-2017-8812",
    "CVE-2017-8814",
    "CVE-2017-8815",
    "CVE-2017-9841"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0665");

  script_name(english:"FreeBSD : mediawiki -- multiple vulnerabilities (298829e2-ccce-11e7-92e4-000c29649f92)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"mediawiki reports :

security fixes :

T128209: Reflected File Download from api.php. Reported by Abdullah
Hussam.

T165846: BotPasswords doesn't throttle login attempts.

T134100: On private wikis, login form shouldn't distinguish between
login failure due to bad username and bad password.

T178451: XSS when $wgShowExceptionDetails = false and browser sends
non-standard url escaping.

T176247: It's possible to mangle HTML via raw message parameter
expansion.

T125163: id attribute on headlines allow raw.

T124404: language converter can be tricked into replacing text inside
tags by adding a lot of junk after the rule definition.

T119158: Language converter: unsafe attribute injection via glossary
rules.

T180488: api.log contains passwords in plaintext wasn't correctly
fixed.

T180231: composer.json has require-dev versions of PHPUnit with known
security issues. Reported by Tom Hutchison.");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000216.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f53f1a4");
  # https://vuxml.freebsd.org/freebsd/298829e2-ccce-11e7-92e4-000c29649f92.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db3e8336");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki127");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki129");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"mediawiki127<1.27.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki128<1.28.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki129<1.29.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
