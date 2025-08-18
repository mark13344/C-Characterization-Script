/*
 * Created by SharpDevelop.
 * User: Developr
 * Date: 6/26/2025
 * Time: 10:19 AM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System; 
using System.Diagnostics;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;
using System.Security.AccessControl;
using TaskScheduler;
using NetFwTypeLib;





namespace CharacterizerLib
{
    public class Characterizer
    {
        /*public static void Main(String[] args){
            MachineInfo machine = new MachineInfo();
            ProcessInfo procs = new ProcessInfo();
		
            Console.ReadLine();
        }*/

        public class BaseInfo
        {
            //Base Information to collect on every system
            public string Hostname { get; private set; }
            public List<string> IPv4Addresses { get; private set; }
            public List<string> IPv6Addresses { get; private set; }

            public BaseInfo()
            {
                Hostname = Dns.GetHostName();
                IPv4Addresses = new List<string>();
                IPv6Addresses = new List<string>();
                IPAddress[] addresses = Dns.GetHostAddresses(Hostname);

                Refresh();
            }

            public override string ToString()
            {
                return string.Format(
                    "[MachineInfo Hostname={0}, IPv4Addresses={1}, IPv6Addresses={2}]",
                    Hostname,
                    string.Join(", ", IPv4Addresses.ToArray()),
                    string.Join(", ", IPv6Addresses.ToArray()));
            }

            public void Refresh()
            {
                Hostname = Dns.GetHostName();
                IPv4Addresses.Clear();
                IPv6Addresses.Clear();
                //Query API for Hostname and IP addresses in both IPv4 and IPv6
                IPAddress[] addresses = Dns.GetHostAddresses(Hostname);
                foreach (IPAddress addr in addresses)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetwork)
                    {
                        IPv4Addresses.Add(addr.ToString());
                    }
                    else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        IPv6Addresses.Add(addr.ToString());
                    }
                }
            }


        }

        public class ProcessInfo
        {
            public List<ProcDetails> Processes { get; private set; }
            public int ProcessCount { get; private set; }


            public ProcessInfo()
            {
                Processes = new List<ProcDetails>();

                Refresh();
            }

            public override string ToString()
            {
                return base.ToString() + string.Format("\n[ProcessInfo ProcessCount={0}]", ProcessCount);
            }

            public void Refresh()
            {
                //Query Processes through API
                Processes.Clear();
                Process[] procarr = Process.GetProcesses();
                //Add process details to object
                foreach (Process p in procarr)
                {
                    ProcDetails proc = new ProcDetails();
                    try
                    {
                        proc.PID = p.Id;
                        proc.Name = p.ProcessName;
                        proc.Path = GetProcessPath(p);
                        proc.ParentPID = GetParentPID(p.Id);
                        proc.SHA256 = ComputeSHA256(proc.Path);
                        //WMI Query
                        string query = "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + proc.PID;
                        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                proc.CommandLine = obj["CommandLine"] != null ? obj["CommandLine"].ToString() : "N/A";
                            }
                        }

                        string parentQuery = "SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = " + proc.ParentPID;
                        using (ManagementObjectSearcher parentSearch = new ManagementObjectSearcher(parentQuery))
                        {
                            foreach (ManagementObject pobj in parentSearch.Get())
                            {
                                proc.ParentPath = pobj["ExecutablePath"] != null ? pobj["ExecutablePath"].ToString() : "N/A";
                                proc.ParentCommandLine = pobj["CommandLine"] != null ? pobj["CommandLine"].ToString() : "N/A";
                            }
                        }

                        if (!string.IsNullOrEmpty(proc.Path) && File.Exists(proc.Path))
                        {
                            SignatureInfo sigInfo = SignatureHelper.GetSignatureInfo(proc.Path);
                            proc.Signature = sigInfo.IsTrusted ? sigInfo.SignerName : "Unsigned or Untrusted";
                        }
                        else
                        {
                            proc.Signature = "N/A";
                        }


                    }
                    catch (Exception)
                    {

                        throw;
                    }

                    Processes.Add(proc);
                }

                ProcessCount = Processes.Count;
            }



            private string ComputeSHA256(string filepath)
            {	//Read in file and create SHA256 hash based on bytes read
                try
                {
                    using (FileStream stream = File.Open(filepath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (SHA256 sha = SHA256.Create())
                    {
                        byte[] hash = sha.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
                catch
                {
                    return "SHA Error";
                }
            }
            //WMI Query for PPID based on PID
            private int GetParentPID(int pid)
            {
                try
                {
                    string query = "SELECT ParentProcessId from Win32_Process WHERE ProcessId = " + pid;
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            return Convert.ToInt32(obj["ParentProcessId"]);
                        }
                    }
                }
                catch
                {
                    //error processing
                }
                //Not Found
                return -1;
            }
            //Open process and use Kernel API to query Image Name
            private string GetProcessPath(Process process)
            {
                try
                {
                    StringBuilder buffer = new StringBuilder(1024);
                    IntPtr handle = OpenProcess(0x1000, false, process.Id);
                    if (handle == IntPtr.Zero) return "Access Denied";

                    int size = buffer.Capacity;
                    if (QueryFullProcessImageName(handle, 0, buffer, ref size))
                    {
                        CloseHandle(handle);
                        return buffer.ToString();
                    }

                    CloseHandle(handle);
                }
                catch
                {
                    //error
                }

                return "N/A";
            }
            //Kernel DLL APIs
            [DllImport("kernel32.dll")]
            static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

            [DllImport("kernel32.dll")]
            static extern IntPtr OpenProcess(int access, bool inherit, int pid);

            [DllImport("kernel32.dll")]
            static extern bool CloseHandle(IntPtr hObject);




            //Detail Object
            public class ProcDetails
            {
                public string Name { get; set; }
                public int PID { get; set; }
                public string Path { get; set; }
                public string CommandLine { get; set; }
                public string SHA256 { get; set; }
                public int ParentPID { get; set; }
                public string ParentPath { get; set; }
                public string ParentCommandLine { get; set; }
                public string Signature { get; set; }
            }




        }

        public class ServiceInfo
        {
            public List<ServiceDetails> Services;
            public int ServiceCount;

            public ServiceInfo()
            {
                Services = new List<ServiceDetails>();

                Refresh();
            }

            public void Refresh()
            {

                try
                {
                    //API query through ServiceController
                    ServiceController[] service = ServiceController.GetServices();

                    foreach (ServiceController serv in service)
                    {
                        var details = new ServiceDetails();

                        details.ServiceName = serv.ServiceName;
                        details.DisplayName = serv.DisplayName;
                        details.State = serv.Status.ToString();

                        string registryPath = @"SYSTEM\CurrentControlSet\Services\" + details.ServiceName;
                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
                        {
                            if (key != null)
                            {
                                object imagePath = key.GetValue("ImagePath");
                                object startValue = key.GetValue("Start");
                                object description = key.GetValue("Description");

                                if (imagePath != null)
                                {
                                    details.Path = imagePath.ToString();
                                }

                                if (startValue != null)
                                {
                                    int startcode = Convert.ToInt32(startValue);

                                    switch (startcode)
                                    {
                                        case 2: details.Mode = "Automatic"; break;
                                        case 3: details.Mode = "Manual"; break;
                                        case 4: details.Mode = "Disabled"; break;
                                        default: details.Mode = "Unknown"; break;
                                    }
                                }

                                if (description != null)
                                {
                                    details.Description = description.ToString();
                                }
                            }
                        }
                        Services.Add(details);
                    }
                }
                catch
                {
                    //error
                }

                ServiceCount = Services.Count;



            }

            public class ServiceDetails
            {
                public string ServiceName { set; get; }
                public string DisplayName { set; get; }
                public string Path { set; get; }
                public string Mode { set; get; }
                public string State { set; get; }
                public string Description { set; get; }
            }

        }

        public class UserInfo
        {

            public List<UserDetails> Users { get; private set; }
            public int UsersCount { get; private set; }

            public UserInfo()
            {
                Users = new List<UserDetails>();
                CollectUsers();
            }

            public void refresh()
            {
                Users.Clear();
                CollectUsers();
            }

            private void CollectUsers()
            {
                //Values required for DLL INTOP Functions
                int entriesRead, totalEnteries, resumeHandle = 0;
                IntPtr buffer = IntPtr.Zero;
                //Check Status for 0 == Good and Pointer for non-zero value
                int status = NetUserEnum(null, 0, 2, out buffer, -1, out entriesRead, out totalEnteries, ref resumeHandle);
                if (status == 0 && buffer != IntPtr.Zero)
                {
                    IntPtr currentPtr = buffer;
                    int structsize = Marshal.SizeOf(typeof(USER_INFO_0));
                    //Iterate pointer by number of entries. Read memory to the same size of struct
                    for (int i = 0; i < entriesRead; i++)
                    {
                        USER_INFO_0 user = (USER_INFO_0)Marshal.PtrToStructure(currentPtr, typeof(USER_INFO_0));
                        var detailed = GetUserDetails(user.usri0_name);
                        Users.Add(detailed);
                        currentPtr = new IntPtr(currentPtr.ToInt64() + structsize);
                    }
                    UsersCount = Users.Count;
                    //Free Created Buffer
                    NetApiBufferFree(buffer);
                }
            }

            private UserDetails GetUserDetails(string username)
            {
                //Read via INTOP Functions similar to above
                IntPtr buffer = IntPtr.Zero;
                int status = NetUserGetInfo(null, username, 2, out buffer);

                if (status == 0 && buffer != IntPtr.Zero)
                {
                    USER_INFO_2 info = (USER_INFO_2)Marshal.PtrToStructure(buffer, typeof(USER_INFO_2));

                    var user = new UserDetails
                    {
                        Username = info.usri2_name,
                        PasswordAge = info.usri2_priv,
                        Comments = info.usri2_comment,
                        Flag = info.usri2_flags,
                        AuthFlags = info.usri2_auth_flags,
                        FullName = info.usri2_full_name,
                        UserComment = info.usri2_usr_comment,
                        Workstations = info.usri2_workstations,
                        LastLogon = info.usri2_last_logon > 0 ? new DateTime(1970, 1, 1).AddSeconds(info.usri2_last_logon).ToLocalTime().ToString("g") : "Never",
                        LastLogoff = info.usri2_last_logoff > 0 ? new DateTime(1970, 1, 1).AddSeconds(info.usri2_last_logoff).ToLocalTime().ToString("g") : "Never",
                        AccountExpires = info.usri2_acct_expires,
                        MaxStorage = info.usri2_max_storage,
                        BadPasswordCount = info.usri2_bad_pw_count,
                        LogonCount = info.usri2_num_logons,
                        LogonServer = info.usri2_logon_server,
                        SID = GetUserSid(username),
                        isEnabled = (info.usri2_flags & 0x0020) == 0,
                        passwordExpires = (info.usri2_flags & 0x10000) == 0,
                        canChangePassword = (info.usri2_flags & 0x0040) == 0
                    };

                    NetApiBufferFree(buffer);
                    return user;
                }

                return new UserDetails { Username = username };

            }

            public static string GetUserSid(string username)
            {
                try
                {
                    System.Security.Principal.NTAccount account = new System.Security.Principal.NTAccount(username);
                    SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    return sid.Value;
                }
                catch (Exception)
                {

                    return "SID Lookup Failed";
                }

            }






            public class UserDetails
            {
                public string Username { get; set; }
                public string SID { get; set; }
                public int PasswordAge { get; set; }
                public int Privilege { get; set; }
                public string Comments { get; set; }
                public int Flag { get; set; }
                public int AuthFlags { get; set; }
                public string FullName { get; set; }
                public string UserComment { get; set; }
                public string Workstations { get; set; }
                public string LastLogon { get; set; }
                public string LastLogoff { get; set; }
                public int AccountExpires { get; set; }
                public int MaxStorage { get; set; }
                public int BadPasswordCount { get; set; }
                public int LogonCount { get; set; }
                public string LogonServer { get; set; }
                public bool isEnabled { get; set; }
                public bool passwordRequired { get; set; }
                public bool passwordExpires { get; set; }
                public bool canChangePassword { get; set; }

            }
            //DLL Imports 
            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] //Unicode Required for C#
            private static extern int NetUserEnum(string servername, int level, int filter, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

            [DllImport("Netapi32.dll")]
            private static extern int NetApiBufferFree(IntPtr Buffer);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct USER_INFO_0
            {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string usri0_name;
            }


            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern int NetUserGetInfo(
                [MarshalAs(UnmanagedType.LPWStr)] string servername,
                [MarshalAs(UnmanagedType.LPWStr)] string username,
                int level,
                out IntPtr bufptr);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool LookupAccountName(
                string lpSystemName,
                string lpAccountName,
                byte[] Sid,
                ref int cbSid,
                StringBuilder ReferencedDomainName,
                ref int cchReferencedDomainName,
                out int peUse);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr ptrSidstr);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr LocalFree(IntPtr hMem);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct USER_INFO_2
            {
                public string usri2_name;
                public string usri2_password;
                public int usri2_password_age;
                public int usri2_priv;
                public string usri2_home_dir;
                public string usri2_comment;
                public int usri2_flags;
                public string usri2_script_path;
                public int usri2_auth_flags;
                public string usri2_full_name;
                public string usri2_usr_comment;
                public string usri2_parms;
                public string usri2_workstations;
                public int usri2_last_logon;
                public int usri2_last_logoff;
                public int usri2_acct_expires;
                public int usri2_max_storage;
                public int usri2_units_per_week;
                public int usri2_bad_pw_count;
                public int usri2_num_logons;
                public string usri2_logon_server;
            }
        }

        public class GroupInfo
        {
            public List<GroupDetails> Groups { get; private set; }
            public int GroupCount { get; private set; }

            public GroupInfo()
            {
                Groups = new List<GroupDetails>();
                refresh();
            }

            public void refresh()
            {
                Groups.Clear();

                IntPtr buffer = IntPtr.Zero;
                int entriesRead, totalEntries, resumeHandle = 0;
                int status = NetLocalGroupEnum(null, 1, out buffer, -1, out entriesRead, out totalEntries, ref resumeHandle);

                if (status == 0 && buffer != IntPtr.Zero)
                {
                    int structSize = Marshal.SizeOf(typeof(LOCALGROUP_INFO_1));
                    IntPtr currentPtr = buffer;

                    for (int i = 0; i < entriesRead; i++)
                    {
                        LOCALGROUP_INFO_1 group = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(LOCALGROUP_INFO_1));

                        GroupDetails g = new GroupDetails();
                        g.GroupName = group.lgrpi1_name;
                        g.Description = group.lgrpi1_comment;
                        g.Members = GetGroupMembers(group.lgrpi1_name);
                        g.SID = GetGroupSid(g.GroupName);

                        if (g.SID.StartsWith("S-1-5-32"))
                            g.Type = "Built-In";
                        else if (g.SID.StartsWith("S-1-5-21"))
                            g.Type = "Local";
                        else
                            g.Type = "Domain";

                        Groups.Add(g);

                        currentPtr = new IntPtr(currentPtr.ToInt64() + structSize);
                    }

                    NetApiBufferFree(buffer);
                }
                GroupCount = Groups.Count;
            }

            public List<string> GetGroupMembers(string groupname)
            {
                List<string> members = new List<string>();
                IntPtr buffer = IntPtr.Zero;
                int entriesRead, totalEntries, resumeHandle = 0;

                int status = NetLocalGroupGetMembers(null, groupname, 1, out buffer, -1, out entriesRead, out totalEntries, ref resumeHandle);

                if (status == 0 && buffer != IntPtr.Zero)
                {
                    int structsize = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_1));
                    IntPtr currentPtr = buffer;

                    for (int i = 0; i < entriesRead; i++)
                    {
                        LOCALGROUP_MEMBERS_INFO_1 member = (LOCALGROUP_MEMBERS_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(LOCALGROUP_MEMBERS_INFO_1));
                        members.Add(member.lgrmi1_name);
                        currentPtr = new IntPtr(currentPtr.ToInt64() + structsize);
                    }

                    NetApiBufferFree(buffer);
                }

                return members;
            }

            public static string GetGroupSid(string groupname)
            {
                try
                {
                    NTAccount account = new NTAccount(groupname);
                    SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    return sid.Value;
                }
                catch
                {
                    return "SID Lookup Failed";
                }
            }



            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_INFO_1
            {
                public string lgrpi1_name;
                public string lgrpi1_comment;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_MEMBERS_INFO_1
            {
                public IntPtr lgrmi1_sid;
                public int lgrmi1_sidusage;
                public string lgrmi1_name;
            }

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
            public static extern int NetLocalGroupEnum(
                string servername,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resumehandle
            );

            [DllImport("Netapi32.dll")]
            public static extern int NetApiBufferFree(IntPtr Buffer);

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
            public static extern int NetLocalGroupGetMembers(
                string servername,
                string groupname,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resumehandle
            );


            public class GroupDetails
            {
                public string GroupName { get; set; }
                public string Description { get; set; }
                public string SID { get; set; }
                public string Type { get; set; }
                public List<string> Members { get; set; }
            }


        }

        public class NetShareInfo
        {
            public List<NetShareDetails> Shares { get; private set; }
            public int ShareCount { get; private set; }

            public NetShareInfo()
            {
                Shares = new List<NetShareDetails>();
                Refresh();
            }


            public void Refresh(string server = null)
            {
                IntPtr buffer = IntPtr.Zero;
                int entriesRead, totalEntries, resumeHandle = 0;
                int level = 502;

                try
                {
                    int result = NetShareEnum(server, level, out buffer, -1, out entriesRead, out totalEntries, ref resumeHandle);

                    if (result == 0 && buffer != IntPtr.Zero)
                    {
                        int structSize = Marshal.SizeOf(typeof(SHARE_INFO_502));
                        IntPtr currentPtr = buffer;

                        for (int i = 0; i < entriesRead; i++)
                        {
                            SHARE_INFO_502 shareInfo = (SHARE_INFO_502)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_502));
                            var sddl = GetShareAcl(shareInfo.shi502_security_descriptor);
                            var share = new NetShareDetails
                            {
                                Name = shareInfo.shi502_netname,
                                Path = shareInfo.shi502_path,
                                Description = shareInfo.shi502_remark,
                                MaxUses = shareInfo.shi502_max_uses,
                                CurrentUses = shareInfo.shi502_current_uses,
                                Type = ShareTypeToString(shareInfo.shi502_type),
                                IsHidden = shareInfo.shi502_netname.EndsWith("$"),
                                IsAdminShare = IsAdminShareName(shareInfo.shi502_netname),
                                Sddl = sddl,
                                ACL = ParseSddlToAclEntries(sddl)
                            };

                            Shares.Add(share);

                            currentPtr = new IntPtr(currentPtr.ToInt64() + structSize);
                        }
                    }
                }
                catch
                {

                    throw;
                }

                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
                ShareCount = Shares.Count;

            }



            private static bool IsAdminShareName(string name)
            {
                return name.Equals("ADMIN$", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("C$", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("IPC$", StringComparison.OrdinalIgnoreCase);
            }

            private static string ShareTypeToString(uint type)
            {
                switch (type)
                {
                    case 0: return "Disk Drive";
                    case 1: return "Printer";
                    case 2: return "Device";
                    case 3: return "IPC";
                    default: return "Unknown";
                }
            }

            private static string GetShareAcl(IntPtr securityDescriptorPtr)
            {
                if (securityDescriptorPtr == IntPtr.Zero)
                    return "No ACL (null descriptor)";
                const uint SDDL_REVISION_1 = 1;
                const uint OWNER_SECURITY_INFORMATION = 0x00000001;
                const uint GROUP_SECURITY_INFORMATION = 0x00000002;
                const uint DACL_SECURITY_INFORMATION = 0x00000004;

                IntPtr sddlPtr;
                uint sddlLen;

                bool success = ConvertSecurityDescriptorToStringSecurityDescriptor(
                    securityDescriptorPtr,
                    SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    out sddlPtr,
                    out sddlLen);

                if (!success || sddlPtr == IntPtr.Zero)
                    return "Failed to Parse ACL";
                string sddl = Marshal.PtrToStringUni(sddlPtr);
                LocalFree(sddlPtr);

                return sddl;
            }

            private static List<AclEntry> ParseSddlToAclEntries(string sddl)
            {
                List<AclEntry> entries = new List<AclEntry>();

                try
                {
                    CommonSecurityDescriptor descriptor = new CommonSecurityDescriptor(false, false, sddl);

                    foreach (CommonAce ace in descriptor.DiscretionaryAcl)
                    {
                        string sid = ace.SecurityIdentifier.Value;
                        string resolvedName;
                        try
                        {
                            resolvedName = ace.SecurityIdentifier.Translate(typeof(NTAccount)).ToString();
                        }
                        catch
                        {
                            resolvedName = sid;
                        }

                        string accessType = ace.AceType == AceType.AccessAllowed ? "Allow" : ace.AceType == AceType.AccessDenied ? "Deny" : ace.AceType.ToString();
                        entries.Add(new AclEntry
                        {
                            Identity = resolvedName,
                            Rights = ace.AccessMask.ToString("X"),
                            AccessType = accessType,
                            Inheritance = ace.AceFlags.ToString()
                        });
                    }
                }
                catch
                {
                    entries.Add(new AclEntry { Identity = "Invalid ACL or Parsing Failed" });
                }

                return entries;
            }

            public void Print()
            {
                if (Shares == null || Shares.Count == 0)
                {
                    Console.WriteLine("No shares found. \n");
                    return;
                }

                foreach (var share in Shares)
                {
                    Console.WriteLine("Share Name   : {0}", share.Name);
                    Console.WriteLine("Path         : {0}", share.Path);
                    Console.WriteLine("Description  : {0}", share.Description);
                    Console.WriteLine("Hidden       : {0}", share.IsHidden ? "Yes" : "No");
                    Console.WriteLine("Admin Share  : {0}", share.IsAdminShare ? "Yes" : "No");
                    Console.WriteLine("Type         : {0}", share.Type);
                    Console.WriteLine("Max Uses     : {0}", share.MaxUses);
                    Console.WriteLine("Current Uses : {0}", share.CurrentUses);
                    Console.WriteLine("SDDL         : {0}", share.Sddl);
                    Console.WriteLine("ACL Entries  :");

                    if (share.ACL != null && share.ACL.Count > 0)
                    {
                        foreach (var acl in share.ACL)
                        {
                            Console.WriteLine("  - Identity    : {0}", acl.Identity);
                            Console.WriteLine("    Access Type : {0}", acl.AccessType);
                            Console.WriteLine("    Rights      : {0}", acl.Rights);
                            Console.WriteLine("    Inheritance : {0}", acl.Inheritance);
                            Console.WriteLine();
                        }
                    }
                    else
                    {
                        Console.WriteLine("  (No ACL entries parsed or found)");
                    }

                    Console.WriteLine(new string('-', 60));
                }
            }



            public class NetShareDetails
            {
                public string Name { get; set; }
                public string Path { get; set; }
                public string Description { get; set; }
                public string Type { get; set; }
                public uint MaxUses { get; set; }
                public uint CurrentUses { get; set; }
                public bool IsHidden { get; set; }
                public bool IsAdminShare { get; set; }
                public string Sddl { get; set; }
                public List<AclEntry> ACL { get; set; }
            }

            public class AclEntry
            {
                public string Identity { get; set; }
                public string Rights { get; set; }
                public string AccessType { get; set; }
                public string Inheritance { get; set; }
            }


            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr LocalFree(IntPtr hMem);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
                IntPtr SecurityDescriptor,
                uint RequestedRevision,
                uint SecurityInformation,
                out IntPtr StringSecurityDescriptor,
                out uint StringSecurityDescriptorLen);

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
            public static extern int NetApiBufferFree(IntPtr Buffer);

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
            public static extern int NetShareEnum(
                string servername,
                int level,
                out IntPtr bufPtr,
                int prefmaxlen,
                out int entriesRead,
                out int totalEntries,
                ref int resumeHandle);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SHARE_INFO_502
            {
                public string shi502_netname;
                public uint shi502_type;
                public string shi502_remark;
                public uint shi502_permissions;
                public uint shi502_max_uses;
                public uint shi502_current_uses;
                public string shi502_path;
                public string shi502_passwd;
                public uint shi502_reserved;
                public IntPtr shi502_security_descriptor;
            }

        }

        public class SchTaskInfo
        {
            public List<ScheduledTask> Tasks { get; private set; }
            public int TaskCount { get; private set; }

            public SchTaskInfo()
            {
                Tasks = new List<ScheduledTask>();
                Refresh();
            }

            public void Refresh()
            {
                Tasks.Clear();
                try
                {
                    if (Environment.OSVersion.Version.Major >= 6)
                        CollectUsingCom();
                    else
                        Console.WriteLine("Using ALT: Schtasks");
                    CollectUsingSchtasks();
                }
                catch
                {
                    CollectUsingSchtasks();
                }
            }

            private void CollectUsingCom()
            {
                TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
                if (scheduler == null)
                {
                    CollectUsingSchtasks();
                    return;
                }

                scheduler.Connect();
                ITaskFolder rootFolder = scheduler.GetFolder("\\");
                EnumerateFolder(rootFolder);
            }

            private void EnumerateFolder(ITaskFolder folder)
            {
                IRegisteredTaskCollection tasks = folder.GetTasks(1);
                for (int i = 1; i <= tasks.Count; i++)
                {
                    IRegisteredTask task = tasks[i];
                    ITaskDefinition definition = task.Definition;
                    IActionCollection actions = definition.Actions;

                    string command = "N/A";
                    string arguments = "";
                    string workingDir = "";

                    if (actions.Count > 0)
                    {
                        IAction action = actions[1];
                        if (action.Type == _TASK_ACTION_TYPE.TASK_ACTION_EXEC)
                        {
                            IExecAction execAction = (IExecAction)action;
                            command = execAction.Path ?? "";
                            arguments = execAction.WorkingDirectory ?? "";
                        }
                    }

                    ScheduledTask taskEntry = new ScheduledTask();
                    taskEntry.Name = task.Name;
                    taskEntry.Path = task.Path;
                    taskEntry.State = task.State.ToString();
                    taskEntry.Command = command;
                    taskEntry.UserId = definition.Principal.UserId ?? "";
                    taskEntry.Author = definition.RegistrationInfo.Author ?? "";
                    taskEntry.Description = definition.RegistrationInfo.Description ?? "";
                    taskEntry.Arguments = arguments;
                    taskEntry.WorkingDir = workingDir;

                    Tasks.Add(taskEntry);
                }

                ITaskFolderCollection subFolders = folder.GetFolders(0);
                for (int i = 1; i <= subFolders.Count; i++)
                {
                    EnumerateFolder(subFolders[i]);
                }

            }


            private void CollectUsingSchtasks()
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo("schtasks", "/query /fo CSV /v")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (Process proc = Process.Start(psi))
                    {
                        using (StreamReader reader = proc.StandardOutput)
                        {
                            string line;
                            bool skipHeader = true;

                            while ((line = reader.ReadLine()) != null)
                            {
                                if (skipHeader) { skipHeader = false; continue; }
                                if (string.IsNullOrEmpty(line)) continue;

                                string[] fields = ParseCsvLine(line);
                                if (fields.Length < 5) continue;

                                ScheduledTask task = new ScheduledTask();
                                task.Name = fields[1].Trim('"');
                                task.Path = fields[1].Trim('"');
                                task.UserId = fields[2].Trim('"');
                                task.State = fields[3].Trim('"');
                                task.Author = fields[7].Trim('"');
                                task.Description = fields.Length > 10 ? fields[10].Trim('"') : "";
                                string fullCommand = fields[8].Trim('"');
                                string startIn = fields.Length > 9 ? fields[9].Trim('"') : "";

                                string command = fullCommand;
                                string args = "";

                                if (fullCommand.StartsWith("\""))
                                {
                                    int endQuote = fullCommand.IndexOf("\"", 1);
                                    if (endQuote > 0 && endQuote + 1 < fullCommand.Length)
                                    {
                                        command = fullCommand.Substring(0, endQuote + 1);
                                        args = fullCommand.Substring(endQuote + 1).TrimStart();
                                    }
                                }
                                else
                                {
                                    int space = fullCommand.IndexOf(" ");
                                    if (space > 0)
                                    {
                                        command = fullCommand.Substring(0, space);
                                        args = fullCommand.Substring(space + 1);
                                    }
                                }

                                task.Command = command;
                                task.Arguments = args;
                                task.WorkingDir = startIn;

                                Tasks.Add(task);
                            }
                        }
                    }
                }
                catch
                {

                }
            }

            private string[] ParseCsvLine(string line)
            {
                List<string> parts = new List<string>();
                StringBuilder sb = new StringBuilder();
                bool inQuotes = false;

                for (int i = 0; i < line.Length; i++)
                {
                    char c = line[i];

                    if (c == '\"')
                    {
                        inQuotes = !inQuotes;
                    }
                    else if (c == ',' && !inQuotes)
                    {
                        parts.Add(sb.ToString());
                        sb.Length = 0;
                    }
                    else
                    {
                        sb.Append(c);
                    }


                }
                parts.Add(sb.ToString());
                return parts.ToArray();
            }


            public class ScheduledTask
            {
                public string Name { get; set; }
                public string Path { get; set; }
                public string Arguments { get; set; }
                public string WorkingDir { get; set; }
                public string Author { get; set; }
                public string Description { get; set; }
                public string Command { get; set; }
                public string UserId { get; set; }
                public string State { get; set; }
            }
        }

        public class DriverInfo
        {
            public List<DriverDetails> details { get; set; }
            public int detailsCount { get; set; }

            //Service type constants
            const int SERVICE_KERNEL_DRIVER = 0x00000001;
            const int SERVICE_FILE_SYSTEM_DRIVER = 0x00000002;
            const int SERVICE_DRIVER = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER;
            // Service State
            const int SERVICE_STATE_ALL = 0x00000003;

            // Service start types
            const int SERVICE_AUTO_START = 0x00000002;
            const int SERVICE_DEMAND_START = 0x00000003;
            const int SERVICE_DISABLED = 0x00000004;

            // Access rights
            const int SC_MANAGER_ENUMERATE_SERVICE = 0x0004;

            public DriverInfo()
            {
                details = new List<DriverDetails>();
                Refresh();
            }


            public void Refresh()
            {
                details.Clear();
                // Open handle to Service Control Manager
                IntPtr scmHandle = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);

                if (scmHandle == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to open SCM");
                    return;
                }

                int bytesNeeded = 0;
                int servicesReturned = 0;
                int resumeHandle = 0;

                EnumServicesStatus(scmHandle, SERVICE_DRIVER, SERVICE_STATE_ALL,
                    IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, ref resumeHandle);

                IntPtr buffer = Marshal.AllocHGlobal(bytesNeeded);

                bool success = EnumServicesStatus(scmHandle, SERVICE_DRIVER, SERVICE_STATE_ALL,
                    buffer, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle);

                if (!success)
                {
                    Console.WriteLine("EnumServicesStatus failed.");
                    Marshal.FreeHGlobal(buffer);
                    CloseServiceHandle(scmHandle);
                    return;
                }

                int structSize = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS));
                IntPtr current = buffer;
                // Enumerate Services
                for (int i = 0; i < servicesReturned; i++)
                {
                    ENUM_SERVICE_STATUS status = (ENUM_SERVICE_STATUS)Marshal.PtrToStructure(current, typeof(ENUM_SERVICE_STATUS));

                    IntPtr serviceHandle = OpenService(scmHandle, status.lpServiceName, 0x0001);

                    if (serviceHandle != IntPtr.Zero)
                    {
                        int sizeNeeded;
                        QueryServiceConfig(serviceHandle, IntPtr.Zero, 0, out sizeNeeded);

                        IntPtr qscPtr = Marshal.AllocHGlobal(sizeNeeded);
                        //Enumerate Service Information
                        if (QueryServiceConfig(serviceHandle, qscPtr, sizeNeeded, out sizeNeeded))
                        {
                            QUERY_SERVICE_CONFIG qsc = (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(qscPtr, typeof(QUERY_SERVICE_CONFIG));

                            DriverDetails record = new DriverDetails();

                            record.ServiceName = status.lpServiceName;
                            record.State = GetServiceStateString(status.ServiceStatus.dwCurrentState);
                            record.DisplayName = status.lpDisplayName;
                            record.PathToDriver = NormalizeDriverPath(qsc.lpBinaryPathName);
                            record.StartType = GetStartTypeString(qsc.dwStartType);
                            record.ServiceType = GetServiceTypeString(qsc.dwServiceType);
                            try
                            {
                                record.FileVersion = FileVersionInfo.GetVersionInfo(record.PathToDriver);
                            }
                            catch
                            {
                                record.FileVersion = null;
                            }

                            details.Add(record);
                        }
                        Marshal.FreeHGlobal(qscPtr);
                        CloseServiceHandle(serviceHandle);
                    }

                    current = new IntPtr(current.ToInt64() + structSize);
                }
                Marshal.FreeHGlobal(buffer);
                CloseServiceHandle(scmHandle);

                detailsCount = details.Count;

            }

            private static string GetStartTypeString(int startType)
            {
                switch (startType)
                {
                    case 0x00000000: return "Boot Start";
                    case 0x00000001: return "System Start";
                    case 0x00000002: return "Auto Start";
                    case 0x00000003: return "Manual Start";
                    case 0x00000004: return "Disabled";
                    default: return "Unknown";
                }
            }

            private static string GetServiceTypeString(int serviceType)
            {
                StringBuilder sb = new StringBuilder();

                if ((serviceType & 0x00000001) != 0) sb.Append("Kernel Driver, ");
                if ((serviceType & 0x00000002) != 0) sb.Append("File System Driver, ");
                if ((serviceType & 0x00000010) != 0) sb.Append("Own Process, ");
                if ((serviceType & 0x00000020) != 0) sb.Append("Share Process, ");
                if ((serviceType & 0x00000100) != 0) sb.Append("Interactive Process, ");

                if (sb.Length == 0)
                    return "Unknown";
                else
                    return sb.ToString().TrimEnd(' ', ',');
            }

            private static string GetServiceStateString(int state)
            {
                switch (state)
                {
                    case 1: return "Stopped";
                    case 2: return "Start Pending";
                    case 3: return "Stop Pending";
                    case 4: return "Running";
                    case 5: return "Continue Pending";
                    case 6: return "Pause Pending";
                    case 7: return "Paused";
                    default: return "Unknown";
                }
            }

            private static string NormalizeDriverPath(string rawPath)
            {
                if (string.IsNullOrEmpty(rawPath))
                    return null;

                if (rawPath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                {
                    string systemRoot = Environment.GetEnvironmentVariable("SystemRoot"); // usually C:\Windows
                    return rawPath.Replace(@"\SystemRoot\", systemRoot + @"\");
                }

                if (rawPath.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase))
                {
                    string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                    return rawPath.Replace("%SystemRoot%", systemRoot);
                }

                return rawPath;
            }

            //API Functions

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            struct ENUM_SERVICE_STATUS
            {
                public string lpServiceName;
                public string lpDisplayName;
                public SERVICE_STATUS ServiceStatus;
            }

            [StructLayout(LayoutKind.Sequential)]
            struct SERVICE_STATUS
            {
                public int dwServiceType;
                public int dwCurrentState;
                public int dwControlsAccepted;
                public int dwWin32ExitCode;
                public int dwServiceSpecificExitCode;
                public int dwCheckPoint;
                public int dwWaitHint;
            }

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern IntPtr OpenSCManager(string machinename, string databaseName, int dwAccess);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern bool EnumServicesStatus(
                IntPtr hSCManager,
                int dwServiceType,
                int dwServiceState,
                IntPtr lpServices,
                int cbBufSize,
                out int pcbBytesNeeded,
                out int lpServicesReturned,
                ref int lpResumeHandle);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, int dwDesiredAccess);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern bool QueryServiceConfig(
                IntPtr hService,
                IntPtr lpServiceConfig,
                int cbBufSize,
                out int pcbBytesNeeded);

            [DllImport("advapi32.dll")]
            static extern bool CloseServiceHandle(IntPtr hSCObject);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            struct QUERY_SERVICE_CONFIG
            {
                public int dwServiceType;
                public int dwStartType;
                public int dwErrorControl;
                public string lpBinaryPathName;
                public string lpLoadOrderGroup;
                public int dwTagId;
                public string lpDependencies;
                public string lpServiceStartName;
                public string lpDisplayName;
            }

            //Details Object

            public class DriverDetails
            {
                public string ServiceName { get; set; }
                public string DisplayName { get; set; }
                public string State { get; set; }
                public string StartType { get; set; }
                public string PathToDriver { get; set; }
                public string ServiceType { get; set; }
                public FileVersionInfo FileVersion { get; set; }
            }

        }

        public class NetstatInfo
        {
            //Class Attributes
            public List<NetstatDetails> Connections { get; set; }
            public int ConnectionsCount { get; set; }

            public NetstatInfo()
            {
                Connections = new List<NetstatDetails>();
                Refresh();
            }

            public void Refresh()
            {
                LoadTcpConnections();
                LoadUdpConnections();
            }


            private void LoadTcpConnections()
            {
                int AF_INET = 2;
                int bufferSize = 0;
                //Get buffer size
                uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    //Recall with buffer and check for error code
                    result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                    if (result != 0)
                        return;

                    int numEntries = Marshal.ReadInt32(tcpTablePtr); // First 4 bytes = number of entries
                    int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                    IntPtr rowPtr = new IntPtr(tcpTablePtr.ToInt64() + 4); // Move past numEntries
                    //Clear old connections
                    Connections.Clear();

                    for (int i = 0; i < numEntries; i++)
                    {
                        MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));

                        NetstatDetails detail = new NetstatDetails();
                        detail.Protocol = "TCP";
                        detail.SourceIP = ConvertToIPAddress(tcpRow.localAddr);
                        detail.SourcePort = ConvertPort(tcpRow.localPort).ToString();
                        detail.DestinationIP = ConvertToIPAddress(tcpRow.remoteAddr);
                        detail.DestinationPort = ConvertPort(tcpRow.remotePort).ToString();
                        detail.State = ((TcpState)tcpRow.state).ToString();
                        detail.PID = tcpRow.owningPid.ToString();
                        detail.ProcessPath = GetProcessPath((int)tcpRow.owningPid);

                        Connections.Add(detail);

                        rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);
                    }

                    ConnectionsCount = Connections.Count;
                }
                finally
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }
            }

            private void LoadUdpConnections()
            {
                int AF_INET = 2;
                int buffersize = 0;

                uint result = GetExtendedUdpTable(IntPtr.Zero, ref buffersize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                IntPtr udpTablePtr = Marshal.AllocHGlobal(buffersize);

                try
                {
                    result = GetExtendedUdpTable(udpTablePtr, ref buffersize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                    if (result != 0)
                        return;

                    int numEntries = Marshal.ReadInt32(udpTablePtr);
                    int rowSize = Marshal.SizeOf(typeof(MIB_UDPROW_OWNER_PID));
                    IntPtr rowPtr = new IntPtr(udpTablePtr.ToInt64() + 4);

                    for (int i = 0; i < numEntries; i++)
                    {
                        MIB_UDPROW_OWNER_PID udpRow = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));

                        NetstatDetails detail = new NetstatDetails();
                        detail.SourceIP = ConvertToIPAddress(udpRow.localAddr);
                        detail.SourcePort = ConvertPort(udpRow.localPort).ToString();
                        detail.DestinationIP = "N/A"; // UDP is connectionless
                        detail.DestinationPort = "N/A";
                        detail.State = "N/A"; // UDP has no state
                        detail.PID = udpRow.owningPid.ToString();
                        detail.ProcessPath = GetProcessPath((int)udpRow.owningPid);
                        detail.Protocol = "UDP";

                        Connections.Add(detail);

                        rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                }
            }

            private string ConvertToIPAddress(uint ipAddr)
            {
                byte[] bytes = BitConverter.GetBytes(ipAddr);
                return string.Format("{0}.{1}.{2}.{3}", bytes[0], bytes[1], bytes[2], bytes[3]);
            }

            private ushort ConvertPort(uint port)
            {
                byte[] bytes = BitConverter.GetBytes(port);
                return (ushort)((bytes[0] << 8) | bytes[1]);
            }

            private string GetProcessPath(int pid)
            {
                try
                {
                    Process proc = Process.GetProcessById(pid);
                    return proc.MainModule.FileName;
                }
                catch
                {
                    return "N/A";
                }
            }



            // API Structs and Enums

            //TCP Calls
            [DllImport("iphlpapi.dll", SetLastError = true)]
            private static extern uint GetExtendedTcpTable(
                IntPtr pTcpTable,
                ref int dwOutBufLen,
                bool sort,
                int ipVersion,
                TCP_TABLE_CLASS tblClass,
                uint reserved);

            public enum TCP_TABLE_CLASS
            {
                TCP_TABLE_BASIC_LISTENER,
                TCP_TABLE_BASIC_CONNECTIONS,
                TCP_TABLE_BASIC_ALL,
                TCP_TABLE_OWNER_PID_LISTENER,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                TCP_TABLE_OWNER_PID_ALL,
                TCP_TABLE_OWNER_MODULE_LISTENER,
                TCP_TABLE_OWNER_MODULE_CONNECTIONS,
                TCP_TABLE_OWNER_MODULE_ALL
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_TCPROW_OWNER_PID
            {
                public uint state;
                public uint localAddr;
                public uint localPort;
                public uint remoteAddr;
                public uint remotePort;
                public uint owningPid;
            }

            public enum TcpState : uint
            {
                CLOSED = 1,
                LISTENING = 2,
                SYN_SENT = 3,
                SYN_RECEIVED = 4,
                ESTABLISHED = 5,
                FIN_WAIT1 = 6,
                FIN_WAIT2 = 7,
                CLOSE_WAIT = 8,
                CLOSING = 9,
                LAST_ACK = 10,
                TIME_WAIT = 11,
                DELETE_TCB = 12
            }

            //UDP Calls
            [DllImport("iphlpapi.dll", SetLastError = true)]
            private static extern uint GetExtendedUdpTable(
                IntPtr pUdpTable,
                ref int dwOutBufLen,
                bool sort,
                int ipVersion,
                UDP_TABLE_CLASS tableClass,
                uint reserved);

            public enum UDP_TABLE_CLASS
            {
                UDP_TABLE_BASIC,
                UDP_TABLE_OWNER_PID,
                UDP_TABLE_OWNER_MODULE
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_UDPROW_OWNER_PID
            {
                public uint localAddr;
                public uint localPort;
                public uint owningPid;
            }

            //Details Object
            public class NetstatDetails
            {
                public string Protocol { get; set; }
                public string SourceIP { get; set; }
                public string SourcePort { get; set; }
                public string DestinationIP { get; set; }
                public string DestinationPort { get; set; }
                public string State { get; set; }
                public string PID { get; set; }
                public string ProcessPath { get; set; }

            }
        }

        public class FirewallInfo
        {
            public List<FirewallRulesDetails> Rules;
            public List<FirewallProfileDetails> Profiles;

            public FirewallInfo()
            {
                Rules = new List<FirewallRulesDetails>();
                Profiles = new List<FirewallProfileDetails>();
                Refresh();
            }

            public void Refresh()
            {
                GetFirewallRules();
                GetFirewallProfileDetails();
            }

            //Gather Rules
            private void GetFirewallRules()
            {
                Rules.Clear();
                try
                {
                    INetFwPolicy2 policy = (INetFwPolicy2)Activator.CreateInstance(
                        Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

                    foreach (INetFwRule rule in policy.Rules)
                    {
                        FirewallRulesDetails detail = new FirewallRulesDetails();

                        detail.Name = rule.Name;
                        detail.Description = rule.Description;
                        detail.Program = rule.ApplicationName;
                        detail.Protocol = ProtocolToString(rule.Protocol);
                        detail.LocalIP = rule.LocalAddresses;
                        detail.RemoteIP = rule.RemoteAddresses;
                        detail.Action = rule.Action.ToString();
                        detail.Direction = rule.Direction.ToString();
                        detail.Enabled = rule.Enabled;
                        detail.Profile = ProfileTypesToList(rule.Profiles);
                        detail.Group = rule.Grouping;
                        detail.EdgeTraversal = rule.EdgeTraversal;

                        try
                        {
                            INetFwRule2 r2 = rule as INetFwRule2;
                            if (r2 != null && detail.Program == null && !string.IsNullOrEmpty(r2.ApplicationName))
                                detail.Program = r2.ApplicationName;
                        }
                        catch { /* optional enrichment only */ }

                        Rules.Add(detail);

                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error Collecting Rules: {0}", ex);
                }


            }
            //Gather Profiles Settings
            private void GetFirewallProfileDetails()
            {
                Profiles.Clear();
                try
                {
                    INetFwPolicy2 policy = (INetFwPolicy2)Activator.CreateInstance(
                        Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

                    NET_FW_PROFILE_TYPE2_[] profileTypes = new NET_FW_PROFILE_TYPE2_[]{
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
                };

                    foreach (NET_FW_PROFILE_TYPE2_ prof in profileTypes)
                    {
                        try
                        {
                            FirewallProfileDetails detail = new FirewallProfileDetails();

                            detail.Enabled = policy.get_FirewallEnabled(prof);
                            detail.InAction = ActionToString(policy.get_DefaultInboundAction(prof));
                            detail.OutAction = ActionToString(policy.get_DefaultOutboundAction(prof));

                            string profileKey = null;
                            if (prof == NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) profileKey = "DomainProfile";
                            else if (prof == NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) profileKey = "PrivateProfile";
                            else if (prof == NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) profileKey = "PublicProfile";

                            if (profileKey != null)
                            {
                                detail.Name = profileKey;

                                string baseKey = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\"
                                         + profileKey + @"\Logging";

                                detail.LogPath = (string)Microsoft.Win32.Registry.GetValue(baseKey, "LogFilePath", null);

                                object size = Microsoft.Win32.Registry.GetValue(baseKey, "LogFileSize", null);
                                if (size != null) detail.MaxLogSize = Convert.ToInt32(size);

                                object dropped = Microsoft.Win32.Registry.GetValue(baseKey, "LogDroppedPackets", null);
                                if (dropped != null) detail.LogsDropped = Convert.ToInt32(dropped) != 0 ? true : false;

                                object allowed = Microsoft.Win32.Registry.GetValue(baseKey, "LogAllowedConnections", null);
                                if (allowed != null) detail.SuccessfulConnections = Convert.ToInt32(allowed) != 0 ? true : false;


                            }
                            else
                            {
                                profileKey = "N/A";
                            }

                            Profiles.Add(detail);

                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Error collecting profile {0}: {1}", prof, ex.Message);
                        }


                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Firewall profile collection failed: " + ex.Message);
                }



            }

            //Class Objects
            public class FirewallRulesDetails
            {
                public string Direction { get; set; }
                public string Name { get; set; }
                public string Description { get; set; }
                public string Program { get; set; }
                public string Protocol { get; set; }
                public string LocalIP { get; set; }
                public string RemoteIP { get; set; }
                public string Action { get; set; }
                public bool Enabled { get; set; }
                public List<string> Profile { get; set; }
                public string Group { get; set; }
                public bool EdgeTraversal { get; set; }
            }

            public class FirewallProfileDetails
            {
                public string Name { get; set; }
                public bool Enabled { get; set; }
                public string InAction { get; set; }
                public string OutAction { get; set; }
                public bool LoggingEnabled { get; set; }
                public string LogPath { get; set; }
                public int MaxLogSize { get; set; }
                public bool LogsDropped { get; set; }
                public bool SuccessfulConnections { get; set; }
            }

            //Helper functions

            private static string ProtocolToString(int proto)
            {
                if (proto == -1) return "Any";
                if (proto == 6) return "TCP";
                if (proto == 17) return "UDP";
                if (proto == 1) return "ICMPv4";
                if (proto == 58) return "ICMPv6";
                return proto.ToString();
            }

            private static string ActionToString(NET_FW_ACTION_ action)
            {
                return action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW ? "Allow" : "Block";
            }

            private static string SafeGetString(object value)
            {
                return value == null ? "" : value.ToString();
            }

            private static bool SafeGetEdgeTraversal(INetFwRule r)
            {
                try { return r.EdgeTraversal; }
                catch { return false; }
            }



            //Bitwise operation to determine Profiles
            private List<string> ProfileTypesToList(int profilesBitmask)
            {
                List<string> names = new List<string>();

                if ((profilesBitmask & (int)NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) != 0)
                    names.Add("Domain");
                if ((profilesBitmask & (int)NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) != 0)
                    names.Add("Private");
                if ((profilesBitmask & (int)NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) != 0)
                    names.Add("Public");

                if (names.Count == 0) names.Add("All");

                return names;
            }
        }

        public class RunInfo{
            public List<RunDetails> RunResults;


            /*public static string[] targets = {
                @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"};*/


            public RunInfo()
            {
                RunResults = new List<RunDetails>();
                Refresh();
            }
            
            public void Refresh(){
                GetCurrentUser();
            }

            private void GetCurrentUser()
            {
                RegistryKey baseKey = Registry.CurrentUser;

                string[] targets = {@"Software\Microsoft\Windows\CurrentVersion\Run",
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"};

                
                for(int i = 0; i < targets.Length; i++){

                    using (RegistryKey targetKey = baseKey.OpenSubKey(targets[i]))
                    {
                        if (targetKey != null)
                        {
                            string[] valueNames = targetKey.GetValueNames();

                            for (int j = 0; j < valueNames.Length; j++)
                            {
                                string name = valueNames[j];
                                object val = targetKey.GetValue(name);

                                RunDetails detail = new RunDetails();
                                detail.key = "HKEY_CURRENT_USER\\" + targets[i];
                                detail.value = val != null ? val.ToString() : "";

                                RunResults.Add(detail);
                            }

                        }

                    }
                

                }
            }

            public class RunDetails
            {
                public string key { get; set; }
                public string value { get; set; }
            }
        }





    }


    //Magic
    public static class SignatureHelper
    {
        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

        public static SignatureInfo GetSignatureInfo(string filePath)
        {
            var result = new SignatureInfo { IsTrusted = false, SignerName = "Unknown" };

            // Validate the signature
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            WINTRUST_DATA trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = 0x00000010, // WTPF_USE_DEFAULT_OSVER_CHECK
                dwUIContext = 0,
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                pSignatureSettings = IntPtr.Zero
            };

            uint status = WinVerifyTrust(INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);

            // Clean up
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);
            Marshal.FreeHGlobal(fileInfoPtr);

            // If trusted, extract signer
            if (status == 0) // Success
            {
                result.IsTrusted = true;
                try
                {
                    var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                    result.SignerName = cert.Subject;
                }
                catch
                {
                    result.SignerName = "Signed, signer unknown";
                }
            }

            return result;
        }
    }

    public class SignatureInfo
    {
        public bool IsTrusted { get; set; }
        public string SignerName { get; set; }

        public override string ToString()
        {
            return IsTrusted ? string.Format("Trusted - {0}", SignerName) : "Untrusted or unsigned";
        }
    }

}
