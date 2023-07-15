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
  script_id(173613);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2023-28103", "CVE-2023-28427");

  script_name(english:"FreeBSD : Matrix clients -- Prototype pollution in matrix-js-sdk (5b0ae405-cdc7-11ed-bb39-901b0e9408dc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 5b0ae405-cdc7-11ed-bb39-901b0e9408dc advisory.

  - matrix-react-sdk is a Matrix chat protocol SDK for React Javascript. In certain configurations, data sent
    by remote servers containing special strings in key locations could cause modifications of the
    `Object.prototype`, disrupting matrix-react-sdk functionality, causing denial of service and potentially
    affecting program logic. This is fixed in matrix-react-sdk 3.69.0 and users are advised to upgrade. There
    are no known workarounds for this vulnerability. Note this advisory is distinct from GHSA-2x9c-qwgf-94xr
    which refers to a similar issue. (CVE-2023-28103)

  - matrix-js-sdk is a Matrix messaging protocol Client-Server SDK for JavaScript. In versions prior to 24.0.0
    events sent with special strings in key places can temporarily disrupt or impede the matrix-js-sdk from
    functioning properly, potentially impacting the consumer's ability to process data safely. Note that the
    matrix-js-sdk can appear to be operating normally but be excluding or corrupting runtime data presented to
    the consumer. This vulnerability is distinct from GHSA-rfv9-x7hh-xc32 which covers a similar issue. The
    issue has been patched in matrix-js-sdk 24.0.0 and users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-28427)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://matrix.org/blog/2023/03/28/security-releases-matrix-js-sdk-24-0-0-and-matrix-react-sdk-3-69-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13a4d792");
  # https://vuxml.freebsd.org/freebsd/5b0ae405-cdc7-11ed-bb39-901b0e9408dc.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4727483");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cinny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:element-web");
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
    'cinny<=2.2.4',
    'element-web<1.11.26'
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
