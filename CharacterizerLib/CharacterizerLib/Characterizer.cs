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
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;



namespace CharacterizerLib{
public class Characterizer {
	/*public static void Main(String[] args){
		MachineInfo machine = new MachineInfo();
		ProcessInfo procs = new ProcessInfo();
		
		Console.ReadLine();
	}*/
	
	public class BaseInfo
	{
		public string Hostname { get; private set;}
		public List<string> IPv4Addresses { get; private set; }
		public List<string> IPv6Addresses { get; private set; } 
		
		public BaseInfo(){
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
		
		public virtual void Refresh(){
			Hostname = Dns.GetHostName();
			IPv4Addresses.Clear();
			IPv6Addresses.Clear();
			
			IPAddress[] addresses = Dns.GetHostAddresses(Hostname);
			foreach (IPAddress addr in addresses){
				if (addr.AddressFamily == AddressFamily.InterNetwork){
					IPv4Addresses.Add(addr.ToString());
				} else if (addr.AddressFamily == AddressFamily.InterNetworkV6) {
					IPv6Addresses.Add(addr.ToString());
				}
			}
		}
	 
		
	}
	
	public class ProcessInfo {
		public List<ProcDetails> Processes { get; private set; }
		public int ProcessCount { get; private set; }
		
		
		public ProcessInfo(){
			Processes = new List<ProcDetails>();
			
			Refresh();
		}
		
		public override string ToString()
		{
			return base.ToString() + string.Format("\n[ProcessInfo ProcessCount={0}]", ProcessCount);
		}
		
		public void Refresh(){
			Process[] procarr = Process.GetProcesses();
			
			foreach(Process p in procarr){
				ProcDetails proc = new ProcDetails();
				try {
					proc.PID = p.Id;
					proc.Name = p.ProcessName;
					proc.Path = GetProcessPath(p);
					proc.ParentPID = GetParentPID(p.Id);
					proc.SHA256 = ComputeSHA256(proc.Path);
					
					string query = "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + proc.PID;
					using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query)){
						foreach (ManagementObject obj in searcher.Get()) {
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
					
					if (!string.IsNullOrEmpty(proc.Path) && File.Exists(proc.Path)){
						SignatureInfo sigInfo = SignatureHelper.GetSignatureInfo(proc.Path);
						proc.Signature = sigInfo.IsTrusted ? sigInfo.SignerName : "Unsigned or Untrusted";
					} else {
						proc.Signature = "N/A";
					}
					
					
				} catch (Exception) {
					
					throw;
				}
				
				Processes.Add(proc);
			} 
			
			ProcessCount = Processes.Count;
		}
		

		
		private string ComputeSHA256(string filepath)
    {
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
		
		private int GetParentPID(int pid){
			try{
				string query = "SELECT ParentProcessId from Win32_Process WHERE ProcessId = " + pid;
				using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
				{
					foreach (ManagementObject obj in searcher.Get()) {
						return Convert.ToInt32(obj["ParentProcessId"]);
					}
				}
			} catch {
				//error processing
			}
			
			return -1;
		}
		
		private string GetProcessPath(Process process){
			try{
				StringBuilder buffer = new StringBuilder(1024);
				IntPtr handle = OpenProcess(0x1000, false, process.Id);
				if (handle == IntPtr.Zero) return "Access Denied";
				
				int size = buffer.Capacity;
				if (QueryFullProcessImageName(handle,0,buffer,ref size)){
					CloseHandle(handle);
					return buffer.ToString();
				}
				
				CloseHandle(handle);
			} catch {
				//error
			}
			
			return "N/A";
		}
		
		[DllImport("kernel32.dll")]
		static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
		
		[DllImport("kernel32.dll")]
    	static extern IntPtr OpenProcess(int access, bool inherit, int pid);

	    [DllImport("kernel32.dll")]
	    static extern bool CloseHandle(IntPtr hObject);

    
    	
    	
		
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
	
	public class ServiceInfo{
		public List<ServiceDetails> Services;
		public int ServiceCount;
		
		public ServiceInfo(){
			Services = new List<ServiceDetails>();
			
			Refresh();
		}
		
		public void Refresh(){
			
			try{
				ServiceController[] service = ServiceController.GetServices();
				
				foreach(ServiceController serv in service){
					var details = new ServiceDetails();
					
					details.ServiceName = serv.ServiceName;
					details.DisplayName = serv.DisplayName;
					details.State = serv.Status.ToString();
					
					string registryPath = @"SYSTEM\CurrentControlSet\Services\" + details.ServiceName;
					using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
					{
						if (key != null){
							object imagePath = key.GetValue("ImagePath");
							object startValue = key.GetValue("Start");
							object description = key.GetValue("Description");
							
							if (imagePath != null){
								details.Path = imagePath.ToString();
							}
							
							if (startValue != null){
								int startcode = Convert.ToInt32(startValue);
								
								switch (startcode){
									case 2: details.Mode = "Automatic"; break;
									case 3: details.Mode = "Manual"; break;
									case 4: details.Mode = "Disabled"; break;
									default : details.Mode = "Unknown"; break;
								}
							}
							
							if (description != null){
								details.Description = description.ToString();
							}
						}
					}
					Services.Add(details);
				}
			}catch{
				//error
			}
			
			ServiceCount = Services.Count;
			
			
			
		}
		
		public class ServiceDetails {
			public string ServiceName { set; get;}
			public string DisplayName { set; get;}
			public string Path { set; get;}
			public string Mode { set; get;}
			public string State { set; get;}
			public string Description { set; get;}
		}
		
		}
		
	public class UserInfo {
			
			public List<UserDetails> Users { get; private set; }
			public int UsersCount { get; private set; }
			
			public UserInfo(){
				Users = new List<UserDetails>();
				CollectUsers();
			}
			
			public void refresh(){
				Users.Clear();
				CollectUsers();
			}
			
			private void CollectUsers(){
				int entriesRead, totalEnteries, resumeHandle = 0;
				IntPtr buffer = IntPtr.Zero;
					
				int status = NetUserEnum(null, 0, 2, out buffer, -1, out entriesRead, out totalEnteries, ref resumeHandle);
				if (status == 0 && buffer != IntPtr.Zero){
					IntPtr currentPtr = buffer;
					int structsize = Marshal.SizeOf(typeof(USER_INFO_0));
					
					for (int i = 0; i < entriesRead; i++){
						USER_INFO_0 user = (USER_INFO_0)Marshal.PtrToStructure(currentPtr, typeof(USER_INFO_0));
						var detailed = GetUserDetails(user.usri0_name);
						Users.Add(detailed);
						currentPtr = new IntPtr(currentPtr.ToInt64() + structsize);
					}
				 	UsersCount = Users.Count;
					NetApiBufferFree(buffer);
				}
			}
			
			private UserDetails GetUserDetails(string username)
			{
				IntPtr buffer  = IntPtr.Zero;
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
		                LastLogon = info.usri2_last_logon > 0 ? new DateTime(1970,1,1).AddSeconds(info.usri2_last_logon).ToLocalTime().ToString("g"): "Never",
		                LastLogoff = info.usri2_last_logoff > 0 ? new DateTime(1970,1,1).AddSeconds(info.usri2_last_logoff).ToLocalTime().ToString("g"): "Never",
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
				try {
					System.Security.Principal.NTAccount account = new System.Security.Principal.NTAccount(username);
					SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
					return sid.Value;
				} catch (Exception) {
					
					return "SID Lookup Failed";
				}
				
			}

			
			
			
			
			
			public class UserDetails {
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
			
			[DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
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

	
	}
}

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

