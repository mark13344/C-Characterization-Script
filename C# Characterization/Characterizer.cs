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



public class MachineInfo
{
	public string Hostname { get; private set;}
	public List<string> IPv4Addresses { get; private set; }
	public List<string> IPv6Addresses { get; private set; } 
	public string Timestamp { get; private set; } 
	
	public MachineInfo(){
		Hostname = Dns.GetHostName();
		IPv4Addresses = new List<string>();
		IPv6Addresses = new List<string>();
		IPAddress[] addresses = Dns.GetHostAddresses(Hostname);
		
		foreach (IPAddress addr in addresses){
			if (addr.AddressFamily == AddressFamily.InterNetwork)
			{
				IPv4Addresses.Add(addr.ToString());
			}
			else if (addr.AddressFamily == AddressFamily.InterNetworkV6){
				IPv6Addresses.Add(addr.ToString());
			}
		}
		
		Timestamp = DateTime.Now.ToString("o");
	}
	
	public override string ToString()
    {
        return string.Format(
            "[MachineInfo Hostname={0}, IPv4Addresses={1}, IPv6Addresses={2}, Timestamp={3}]",
            Hostname,
            string.Join(", ", IPv4Addresses.ToArray()),
            string.Join(", ", IPv6Addresses.ToArray()),
            Timestamp);
    }
 
	
}

public class ProcessInfo : MachineInfo{
	public List<ProcDetails> Processes { get; private set; }
	public int ProcessCount { get; private set; }
	
	
	public ProcessInfo() : base(){
		Processes = new List<ProcDetails>();
		
		try{
			Process[] procs = Process.GetProcesses();
			
			foreach(Process p in procs){
				try{
					var details = new ProcDetails();
					details.Name = p.ProcessName;
					details.PID = p.Id;
					details.CommandLine = GetProcessCommandLine(details.PID);
					
					try{
						details.Path = p.MainModule.FileName;
					} catch {
						details.Path = "Access Denied";
					}
					
					if (File.Exists(details.Path)){
						details.SHA256 = ComputeSHA256(details.Path);
					} else {
						details.SHA256 = "N/A";
					}
					
					details.ParentPID = GetParentProcessId(p.Id);
					
					details.ParentPath = 
				}
			}
		}
	}
	
	public override string ToString()
	{
		return base.ToString() + string.Format("\n[ProcessInfo ProcessCount={0}]", ProcessCount);
	}
 
	
	private string ComputeSHA256(string filepath){
		using (FileStream stream = File.Open(filepath)){
			SHA256Managed sha = new SHA256Managed();
			byte[] hash = sha.ComputeHash(stream);
			return BitConverter.ToString(hash).Replace("-","").ToLowerInvariant();
		}
	}
	
	private string GetProcessExecutablePath(int pid)
    {
        if (pid < 0) return "N/A";

        try
        {
            string query = "SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + pid;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["ExecutablePath"] != null ? obj["ExecutablePath"].ToString() : "N/A";
            }
        }
        catch
        {
            // ignore errors
        }
        return "N/A";
    }
	
	private int GetParentProcessId(int pid)
    {
        try
        {
            string query = "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = " + pid;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject obj in searcher.Get())
            {
                return Convert.ToInt32(obj["ParentProcessId"]);
            }
        }
        catch
        {
            // ignore errors
        }
        return -1; // Unknown
    }
	
	private int GetParentProcessId(int pid){
		try{
			string query = " SELECT ParentProcessId from Win32_Process WHERE ProcessId = " + pid;
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
			foreach (ManagementObject obj in searcher.Get()){
				return obj["ExecutablePath"] != null ? obj["ExecutablePath"].ToString(): "N/A";
			}
		}catch{
			//ignore errors
		}
		return "N/A"
	}
	
	private string GetProcessCommandLine(int pid){
		try{
			string query = " SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + pid;
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
			foreach (ManagementObject obj in searcher.Get()){
				return obj["CommandLine"] != null ? obj["CommandLine"].ToString() : "N/A";
			} catch {
				// ignore errors
			}
			return "N/A"
		} 
	}
	
	public class ProcDetails
	{
		public string Name { get; private set; };
		public int PID { get; private set; };
		public int PPID { get; private set; };
		public string Path { get; private set; };
		public string CommandLine { get; private set; };
		public string SHA256 { get; private set; };
		public int ParentPID { get; private set; };
		public string ParentPath { get; private set; };
		public string ParentCommandLine { get; private set; };
		
	}
	
	


}


