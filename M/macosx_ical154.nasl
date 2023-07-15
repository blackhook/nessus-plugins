#TRUSTED 410e862193e7dd690e0980f919b43458ef3206e5c4f8214fe6f6541079d91b19957378e881347bfe2c7dcde63ebf8ef07da8a5079199311fb1ef8842878254a9210e62af40fa698b789fa683c935d25b0c6db27361762981efa9a1f99487fcbf509579625396d2428111cf8de60c1da4072bab59409e4431f3e59a89cbde2798fa5039ff3e35b6f6cc2c1b54c0f5eaad07e4f17740d0a57db539799793ff9df1df3b7be3f03ab3d14e44b3cf9199016174bed6e73a7262e875826640ab15074f339036dbce8deb6b604297eddfa9c63df1a19438f354f6fa3f47552746b29fcc87050328ad1b787cebc69b3964cb0f115481c0d73cebb9ba191907d92712befa383ded6d3c8f32022740b23087e8e08fbf5417e4d57b246324e687b93274b745af0d1baf4db7a48d0196c7f8ad3ee36ba3dd3259fccd05ca91ac91d2d825bc805f12a0eaf79875c94e520a54ab87816dd0b5915e8ebc5cb3f50cd2faaa8eaa0ab7e67a94bfc7d423a2098addfa2f29a01a24b9d49b627df4bd66439eaf2f3704755a142692991235746807493f230cee25c2925c2901849dff81701093b205567cad2e494b72c7633a9aa96793ac59567b6fd9231db848c791d73795b3e6e5e25e38e479f60e9ebbfa4325567af7010ec1763514ea86ba380dbb7619028733ddbd02e284ea57e908194f2b5f91188a2110cd55f2521a17a21f4e674833a4b7e3
#TRUST-RSA-SHA256 8d0c750d719205877b21f833014082c664482a0cff654711d0c286b7b48950ced4bfb64ae6e5197580b188ce5dd0071b32b3f041f20c4bca931dea4bda4ee67913769dcd5a098e48d1a8e82a110704bbbb3e352fc5f1ee9f885e3acb99368f8c46852baf9ca8e99d82e96a02cfda05751e3189953612fdb7dfa091e410961471ad2f0b0873e61192e61f7c6edcd047a2b852f61d54944dc0405cc36ff2c78881e4a29986ed6a19fd139d28badb468c49b9d9927f931fbbcbff5f087e1482f6b3d98105343262c4a0e47bb78ef73709e068f08a703295b19188bb0a0fdc79525cbc3e75b7a912f4a877d991a9c4e46d7350ec8e140073d9b2f233c1d28fb682cf3e06c9ab81f8814746dbe333655baca6ae1a4920d40abceee121eb9b05e40d5184eb75b5a2ee81fc19eb72331297cba57f674af4d4675517bd17e7e10e4637bd40f45f783e14bbe6c4ecc1daaebb89798f60be7b310c2d1adf66eded40e9d0c8c1ccdeb0750fc09c6fa0ae86b88048a0feeb25bc0c19a085eeffc7ab9ab5cf0294652e8425655b563235d110523b643e7df4b71883e08585c4260930bdc249a2eda26a9f9516925e69eb28138fe8e14422c5533866cd54360dc0efa256d68f31b9f0baf588408e72c7ea2fe9e1e57be5ca39a15dd00789280812ff9d3083d1efd1e861382abe1d1fd24954cced36d2d9abdef7d57a9363f397bb9623bb81f8ec
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15786);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2004-1021");
 script_bugtraq_id(11728);
 script_xref(name:"Secunia", value:"13277");

 script_name(english:"iCal < 1.5.4");
 script_summary(english:"Check for iCal 1.5.4");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of iCal which is older than
version 1.5.4.  Such versions have an arbitrary command execution
vulnerability.  A remote attacker could exploit this by tricking a user
into opening or importing a new iCal calendar.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd087f47");
 script_set_attribute(attribute:"solution", value:"Upgrade to iCal 1.5.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1021");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/11/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/22");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


cmd = GetBundleVersionCmd(file:"iCal.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }
 if ( buf && ereg(pattern:"^(1\.[0-4]\.|1\.5\.[0-3]([^0-9]|$))", string:buf) ) security_warning (0);
}
