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
  script_id(171931);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id("CVE-2022-48337", "CVE-2022-48338", "CVE-2022-48339");

  script_name(english:"FreeBSD : emacs -- multiple vulnerabilities (a75929bd-b6a4-11ed-bad6-080027f5fec9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the a75929bd-b6a4-11ed-bad6-080027f5fec9 advisory.

  - GNU Emacs through 28.2 allows attackers to execute commands via shell metacharacters in the name of a
    source-code file, because lib-src/etags.c uses the system C library function in its implementation of the
    etags program. For example, a victim may use the etags -u * command (suggested in the etags
    documentation) in a situation where the current working directory has contents that depend on untrusted
    input. (CVE-2022-48337)

  - An issue was discovered in GNU Emacs through 28.2. In ruby-mode.el, the ruby-find-library-file function
    has a local command injection vulnerability. The ruby-find-library-file function is an interactive
    function, and bound to C-c C-f. Inside the function, the external command gem is called through shell-
    command-to-string, but the feature-name parameters are not escaped. Thus, malicious Ruby source files may
    cause commands to be executed. (CVE-2022-48338)

  - An issue was discovered in GNU Emacs through 28.2. htmlfontify.el has a command injection vulnerability.
    In the hfy-istext-command function, the parameter file and parameter srcdir come from external input, and
    parameters are not escaped. If a file name or directory name contains shell metacharacters, code may be
    executed. (CVE-2022-48339)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5360");
  # https://vuxml.freebsd.org/freebsd/a75929bd-b6a4-11ed-bad6-080027f5fec9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23889427");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:emacs-canna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:emacs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:emacs-devel-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:emacs-nox");
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
    'emacs-canna<28.2_3,3',
    'emacs-devel-nox<30.0.50.20230101,3',
    'emacs-devel<30.0.50.20230101,3',
    'emacs-nox<28.2_3,3',
    'emacs<28.2_3,3'
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
