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
  script_id(168896);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/17");

  script_cve_id(
    "CVE-2022-23499",
    "CVE-2022-23500",
    "CVE-2022-23501",
    "CVE-2022-23502",
    "CVE-2022-23503",
    "CVE-2022-23504"
  );

  script_name(english:"FreeBSD : typo3 -- multiple vulnerabilities (d9e154c9-7de9-11ed-adca-080027d3a315)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the d9e154c9-7de9-11ed-adca-080027d3a315 advisory.

  - HTML sanitizer is written in PHP, aiming to provide XSS-safe markup based on explicitly allowed tags,
    attributes and values. In versions prior to 1.5.0 or 2.1.1, malicious markup used in a sequence with
    special HTML CDATA sections cannot be filtered and sanitized due to a parsing issue in the upstream
    package masterminds/html5. This allows bypassing the cross-site scripting mechanism of typo3/html-
    sanitizer. The upstream package masterminds/html5 provides HTML raw text elements (`script`, `style`,
    `noframes`, `noembed` and `iframe`) as DOMText nodes, which were not processed and sanitized further. None
    of the mentioned elements were defined in the default builder configuration, that's why only custom
    behaviors, using one of those tag names, were vulnerable to cross-site scripting. This issue has been
    fixed in versions 1.5.0 and 2.1.1. (CVE-2022-23499)

  - TYPO3 is an open source PHP based web content management system. In versions prior to 9.5.38, 10.4.33,
    11.5.20, and 12.1.1, requesting invalid or non-existing resources via HTTP triggers the page error
    handler, which again could retrieve content to be shown as an error message from another page. This leads
    to a scenario in which the application is calling itself recursively - amplifying the impact of the
    initial attack until the limits of the web server are exceeded. This vulnerability is very similar, but
    not identical, to the one described in CVE-2021-21359. This issue is patched in versions 9.5.38 ELTS,
    10.4.33, 11.5.20 or 12.1.1. (CVE-2022-23500)

  - TYPO3 is an open source PHP based web content management system. In versions prior to 8.7.49, 9.5.38,
    10.4.33, 11.5.20, and 12.1.1 TYPO3 is vulnerable to Improper Authentication. Restricting frontend login to
    specific users, organized in different storage folders (partitions), can be bypassed. A potential attacker
    might use this ambiguity in usernames to get access to a different account - however, credentials must be
    known to the adversary. This issue is patched in versions 8.7.49 ELTS, 9.5.38 ELTS, 10.4.33, 11.5.20,
    12.1.1. (CVE-2022-23501)

  - TYPO3 is an open source PHP based web content management system. In versions prior to 10.4.33, 11.5.20,
    and 12.1.1, When users reset their password using the corresponding password recovery functionality,
    existing sessions for that particular user account were not revoked. This applied to both frontend user
    sessions and backend user sessions. This issue is patched in versions 10.4.33, 11.5.20, 12.1.1.
    (CVE-2022-23502)

  - TYPO3 is an open source PHP based web content management system. Versions prior to 8.7.49, 9.5.38,
    10.4.33, 11.5.20, and 12.1.1 are vulnerable to Code Injection. Due to the lack of separating user-
    submitted data from the internal configuration in the Form Designer backend module, it is possible to
    inject code instructions to be processed and executed via TypoScript as PHP code. The existence of
    individual TypoScript instructions for a particular form item and a valid backend user account with access
    to the form module are needed to exploit this vulnerability. This issue is patched in versions 8.7.49
    ELTS, 9.5.38 ELTS, 10.4.33, 11.5.20, 12.1.1. (CVE-2022-23503)

  - TYPO3 is an open source PHP based web content management system. Versions prior to 9.5.38, 10.4.33,
    11.5.20, and 12.1.1 are subject to Sensitive Information Disclosure. Due to the lack of handling user-
    submitted YAML placeholder expressions in the site configuration backend module, attackers could expose
    sensitive internal information, such as system configuration or HTTP request messages of other website
    visitors. A valid backend user account having administrator privileges is needed to exploit this
    vulnerability. This issue has been patched in versions 9.5.38 ELTS, 10.4.33, 11.5.20, 12.1.1.
    (CVE-2022-23504)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://typo3.org/article/typo3-1211-11520-and-10433-security-releases-published
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?300cbbc8");
  # https://vuxml.freebsd.org/freebsd/d9e154c9-7de9-11ed-adca-080027d3a315.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0562a5db");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-11-php81");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-12-php81");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'typo3-11-php81<11.5.20',
    'typo3-12-php81<12.1.2'
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
