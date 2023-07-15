#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(136687);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-11651", "CVE-2020-11652");
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"FreeBSD : salt -- multiple vulnerabilities in salt-master process (6bf55af9-973b-11ea-9f2c-38d547003487)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"F-Secure reports : CVE-2020-11651 - Authentication bypass
vulnerabilities The ClearFuncs class processes unauthenticated
requests and unintentionally exposes the _send_pub() method, which can
be used to queue messages directly on the master publish server. Such
messages can be used to trigger minions to run arbitrary commands as
root.

The ClearFuncs class also exposes the method _prep_auth_info(), which
returns the 'root key' used to authenticate commands from the local
root user on the master server. This 'root key' can then be used to
remotely call administrative commands on the master server. This
unintentional exposure provides a remote un-authenticated attacker
with root-equivalent access to the salt master.

CVE-2020-11652 - Directory traversal vulnerabilities The wheel module
contains commands used to read and write files under specific
directory paths. The inputs to these functions are concatenated with
the target directory and the resulting path is not canonicalized,
leading to an escape of the intended path restriction.

The get_token() method of the salt.tokens.localfs class (which is
exposed to unauthenticated requests by the ClearFuncs class) fails to
sanitize the token input parameter which is then used as a filename,
allowing insertion of '..' path elements and thus reading of files
outside of the intended directory. The only restriction is that the
file has to be deserializable by salt.payload.Serial.loads().");
  script_set_attribute(attribute:"see_also", value:"https://docs.saltstack.com/en/latest/topics/releases/2019.2.4.html");
  script_set_attribute(attribute:"see_also", value:"https://labs.f-secure.com/advisories/saltstack-authorization-bypass");
  # https://blog.f-secure.com/new-vulnerabilities-make-exposed-salt-hosts-easy-targets/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f051ee1b");
  # https://www.tenable.com/blog/cve-2020-11651-cve-2020-11652-critical-salt-framework-vulnerabilities-exploited-in-the-wild
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4975c617");
  # https://vuxml.freebsd.org/freebsd/6bf55af9-973b-11ea-9f2c-38d547003487.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d05a29b3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-salt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"py27-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-salt>=3000<3000.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-salt<2019.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-salt>=3000<3000.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
