#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159723);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-24828");

  script_name(english:"FreeBSD : Composer -- Command injection vulnerability (24a9bd2b-bb43-11ec-af81-0897988a1c07)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 24a9bd2b-bb43-11ec-af81-0897988a1c07 advisory.

  - Composer is a dependency manager for the PHP programming language. Integrators using Composer code to call
    `VcsDriver::getFileContent` can have a code injection vulnerability if the user can control the `$file` or
    `$identifier` argument. This leads to a vulnerability on packagist.org for example where the
    composer.json's `readme` field can be used as a vector for injecting parameters into hg/Mercurial via the
    `$file` argument, or git via the `$identifier` argument if you allow arbitrary data there (Packagist does
    not, but maybe other integrators do). Composer itself should not be affected by the vulnerability as it
    does not call `getFileContent` with arbitrary data into `$file`/`$identifier`. To the best of our
    knowledge this was not abused, and the vulnerability has been patched on packagist.org and Private
    Packagist within a day of the vulnerability report. (CVE-2022-24828)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/composer/composer/security/advisories/GHSA-x7cr-6qr6-2hh6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd820a6f");
  # https://vuxml.freebsd.org/freebsd/24a9bd2b-bb43-11ec-af81-0897988a1c07.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba77d5f7");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php74-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php74-composer2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php80-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php80-composer2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php81-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php81-composer2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'php74-composer2>=2.0.0<2.2.12',
    'php74-composer2>=2.3.0<2.3.5',
    'php74-composer<1.10.26',
    'php80-composer2>=2.0.0<2.2.12',
    'php80-composer2>=2.3.0<2.3.5',
    'php80-composer<1.10.26',
    'php81-composer2>=2.0.0<2.2.12',
    'php81-composer2>=2.3.0<2.3.5',
    'php81-composer<1.10.26'
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
