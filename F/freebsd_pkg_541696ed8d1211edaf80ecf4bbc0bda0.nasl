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
  script_id(169702);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2023-22456", "CVE-2023-22464");

  script_name(english:"FreeBSD : devel/viewvc-devel is vulnerable to cross-site scripting (541696ed-8d12-11ed-af80-ecf4bbc0bda0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 541696ed-8d12-11ed-af80-ecf4bbc0bda0 advisory.

  - ViewVC, a browser interface for CVS and Subversion version control repositories, as a cross-site scripting
    vulnerability that affects versions prior to 1.2.2 and 1.1.29. The impact of this vulnerability is
    mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an
    otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when
    embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be
    challenging to create. Users should update to at least version 1.2.2 (if they are using a 1.2.x version of
    ViewVC) or 1.1.29 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of
    that release lineage should implement a workaround. Users can edit their ViewVC EZT view templates to
    manually HTML-escape changed paths during rendering. Locate in your template set's `revision.ezt` file
    references to those changed paths, and wrap them with `[format html]` and `[end]`. For most users, that
    means that references to `[changes.path]` will become `[format html][changes.path][end]`. (This
    workaround should be reverted after upgrading to a patched version of ViewVC, else changed path names will
    be doubly escaped.) (CVE-2023-22456)

  - ViewVC is a browser interface for CVS and Subversion version control repositories. Versions prior to 1.2.3
    and 1.1.30 are vulnerable to cross-site scripting. The impact of this vulnerability is mitigated by the
    need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted
    ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an
    HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create.
    Users should update to at least version 1.2.3 (if they are using a 1.2.x version of ViewVC) or 1.1.30 (if
    they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage
    should implement one of the following workarounds. Users can edit their ViewVC EZT view templates to
    manually HTML-escape changed path copyfrom paths during rendering. Locate in your template set's
    `revision.ezt` file references to those changed paths, and wrap them with `[format html]` and `[end]`.
    For most users, that means that references to `[changes.copy_path]` will become `[format
    html][changes.copy_path][end]`. (This workaround should be reverted after upgrading to a patched version
    of ViewVC, else copyfrom path names will be doubly escaped.) (CVE-2023-22464)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-22456");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-22464");
  # https://vuxml.freebsd.org/freebsd/541696ed-8d12-11ed-af80-ecf4bbc0bda0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a972e1c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-viewvc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-viewvc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-viewvc-devel");
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
    'py37-viewvc-devel<1.3.0.20230104',
    'py38-viewvc-devel<1.3.0.20230104',
    'py39-viewvc-devel<1.3.0.20230104'
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
