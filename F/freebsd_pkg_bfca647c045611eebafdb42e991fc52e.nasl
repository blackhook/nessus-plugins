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
  script_id(176739);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_cve_id(
    "CVE-2023-33956",
    "CVE-2023-33968",
    "CVE-2023-33969",
    "CVE-2023-33970"
  );

  script_name(english:"FreeBSD : Kanboard -- Multiple vulnerabilities (bfca647c-0456-11ee-bafd-b42e991fc52e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the bfca647c-0456-11ee-bafd-b42e991fc52e advisory.

  - Kanboard is open source project management software that focuses on the Kanban methodology. Versions prior
    to 1.2.30 are subject to an Insecure direct object reference (IDOR) vulnerability present in the
    application's URL parameter. This vulnerability enables any user to read files uploaded by any other user,
    regardless of their privileges or restrictions. By Changing the file_id any user can render all the files
    where MimeType is image uploaded under **/files** directory regard less of uploaded by any user. This
    vulnerability poses a significant impact and severity to the application's security. By manipulating the
    URL parameter, an attacker can access sensitive files that should only be available to authorized users.
    This includes confidential documents or any other type of file stored within the application. The ability
    to read these files can lead to various detrimental consequences, such as unauthorized disclosure of
    sensitive information, privacy breaches, intellectual property theft, or exposure of trade secrets.
    Additionally, it could result in legal and regulatory implications, reputation damage, financial losses,
    and potential compromise of user trust. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-33956)

  - Kanboard is open source project management software that focuses on the Kanban methodology. Versions prior
    to 1.2.30 are subject to a missing access control vulnerability that allows a user with low privileges to
    create or transfer tasks to any project within the software, even if they have not been invited or the
    project is personal. The vulnerable features are `Duplicate to project` and `Move to project`, which both
    utilize the `checkDestinationProjectValues()` function to check his values. This issue has been addressed
    in version 1.2.30. Users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2023-33968)

  - Kanboard is open source project management software that focuses on the Kanban methodology. A stored Cross
    site scripting (XSS) allows an attacker to execute arbitrary Javascript and any user who views the task
    containing the malicious code will be exposed to the XSS attack. Note: The default CSP header
    configuration blocks this javascript attack. This issue has been addressed in version 1.2.30. Users are
    advised to upgrade. Users unable to upgrade should ensure that they have a restrictive CSP header config.
    (CVE-2023-33969)

  - Kanboard is open source project management software that focuses on the Kanban methodology. A
    vulnerability related to a `missing access control` was found, which allows a User with the lowest
    privileges to leak all the tasks and projects titles within the software, even if they are not invited or
    it's a personal project. This could also lead to private/critical information being leaked if such
    information is in the title. This issue has been addressed in version 1.2.30. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-33970)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-33956");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-33968");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-33969");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-33970");
  # https://vuxml.freebsd.org/freebsd/bfca647c-0456-11ee-bafd-b42e991fc52e.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f95d68f0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33970");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php80-kanboard");
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
    'php80-kanboard<1.2.30'
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
